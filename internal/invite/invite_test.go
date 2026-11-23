package invite

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/identity"
)

func testKey(t testing.TB, b byte) identity.PublicKey {
	t.Helper()
	id, err := identity.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id.Public()
}

func peerID(t testing.TB, b byte) string {
	t.Helper()
	k, err := crypto.UnmarshalEd25519PrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestRoundTrip(t *testing.T) {
	k := testKey(t, 1)
	relay, me := peerID(t, 2), peerID(t, 3)
	circuit := "/dns4/relay.example.net/tcp/4001/p2p/" + relay + "/p2p-circuit/p2p/" + me
	for _, in := range []Invite{
		{Key: k},
		{Key: k, Handle: "skaterdude99.example.com"},
		{Key: k, Contact: circuit},
		{Key: k, Handle: "alice.example.org", Contact: "/ip4/203.0.113.7/udp/4001/quic-v1/p2p/" + relay + "/p2p-circuit"},
		{Key: k, Contact: "/dns/mbox.example.org/tcp/443/tls/ws/p2p/" + relay},
	} {
		s := in.String()
		got, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if got != in {
			t.Fatalf("Parse(%q) = %+v, want %+v", s, got, in)
		}
		if strings.ContainsAny(s, " #") {
			t.Fatalf("unsafe characters in %q", s)
		}
	}
	// Unescaped slashes in c, surrounding space, and h after c also parse.
	s := "  " + Prefix + k.String() + "?c=" + circuit + "&h=bob.example.com\n"
	got, err := Parse(s)
	if err != nil || got.Contact != circuit || got.Handle != "bob.example.com" {
		t.Fatalf("lenient forms: %+v %v", got, err)
	}
	if kind, _, err := ClassifyContactHint(circuit); err != nil || kind != ContactRelay {
		t.Fatalf("classify circuit: %q %v", kind, err)
	}
	if kind, _, err := ClassifyContactHint("/dns6/mbox.example.org/udp/443/quic-v1/p2p/" + relay); err != nil || kind != ContactMailbox {
		t.Fatalf("classify mailbox: %q %v", kind, err)
	}
}

func TestRejects(t *testing.T) {
	k := testKey(t, 1)
	ks := k.String()
	relay, me := peerID(t, 2), peerID(t, 3)
	via := "/p2p/" + relay + "/p2p-circuit"
	c := func(hint string) string { return Prefix + ks + "?c=" + url.QueryEscape(hint) }

	// A small-order point (the identity point's encoding).
	small := make([]byte, 32)
	small[0] = 1
	smallText := strings.ToLower(strings.TrimRight(b32std(small), "="))
	// The same key with nonzero padding bits in the last character.
	sloppy := ks[:keyLen-1] + string(rune(ks[keyLen-1]+1))

	cases := map[string]string{
		"empty":            "",
		"wrong scheme":     "openaim://add/" + ks,
		"uppercase scheme": "OPENAIM:add/" + ks,
		"other verb":       "openaim:join/" + ks,
		"short key":        Prefix + ks[:51],
		"long key":         Prefix + ks + "a",
		"uppercase key":    Prefix + strings.ToUpper(ks),
		"non-base32 key":   Prefix + strings.Repeat("1", keyLen),
		"small-order key":  Prefix + smallText,
		"stray key bits":   Prefix + sloppy,
		"empty query":      Prefix + ks + "?",
		"empty value":      Prefix + ks + "?h=",
		"no value":         Prefix + ks + "?h",
		"unknown param":    Prefix + ks + "?x=1",
		"repeated h":       Prefix + ks + "?h=a.example.com&h=b.example.com",
		"fragment":         Prefix + ks + "#frag",
		"plus in value":    Prefix + ks + "?h=a+b.example.com",
		"bad escape":       Prefix + ks + "?h=%zz",
		"punycode handle":  Prefix + ks + "?h=xn--80ak6aa92e.com",
		"punycode label":   Prefix + ks + "?h=paypal.xn--p1ai",
		"uppercase handle": Prefix + ks + "?h=Alice.example.com",
		"one-label handle": Prefix + ks + "?h=localhost",
		"ip handle":        Prefix + ks + "?h=10.0.0.1",
		"non-ascii handle": Prefix + ks + "?h=" + url.QueryEscape("аlice.example.com"),
		"too long":         Prefix + ks + "?h=" + strings.Repeat("a", MaxLen),

		// Contact hints: never a plain (home) IP address.
		"public ipv4":         c("/ip4/203.0.113.7/tcp/4001/p2p/" + me),
		"private ipv4":        c("/ip4/192.168.1.20/tcp/4001/p2p/" + me),
		"ipv6":                c("/ip6/2001:db8::1/udp/4001/quic-v1/p2p/" + me),
		"bare ipv4":           c("/ip4/203.0.113.7"),
		"private relay":       c("/ip4/192.168.1.1/tcp/4001" + via),
		"loopback relay":      c("/ip4/127.0.0.1/tcp/4001" + via),
		"link-local relay":    c("/ip6/fe80::1/tcp/4001" + via),
		"ula relay":           c("/ip6/fd00::1/tcp/4001" + via),
		"cgnat relay":         c("/ip4/100.64.1.1/tcp/4001" + via),
		"unspecified relay":   c("/ip4/0.0.0.0/tcp/4001" + via),
		"mapped private":      c("/ip6/::ffff:10.0.0.1/tcp/4001" + via),
		"relay without id":    c("/dns4/relay.example.net/tcp/4001/p2p-circuit"),
		"ip after circuit":    c("/dns4/relay.example.net/tcp/4001" + via + "/ip4/192.168.1.2/tcp/1"),
		"two hops":            c("/dns4/relay.example.net/tcp/4001" + via + via),
		"mailbox without id":  c("/dns4/mbox.example.org/tcp/443"),
		"mailbox with ip":     c("/dns4/mbox.example.org/tcp/443/ip4/10.0.0.1/tcp/1/p2p/" + relay),
		"one-label dns":       c("/dns4/localhost/tcp/443/p2p/" + relay),
		"unix socket":         c("/unix/tmp/sock"),
		"ip6zone":             c("/ip6zone/eth0/ip6/fe80::1/tcp/1" + via),
		"dnsaddr":             c("/dnsaddr/example.org/p2p/" + relay),
		"not a multiaddr":     Prefix + ks + "?c=relay.example.net",
		"repeated c":          c("/dns4/relay.example.net/tcp/4001"+via) + "&c=x",
		"huge contact":        c("/dns4/" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.com/tcp/4001" + via + "/p2p/" + me),
		"port-only contact":   c("/tcp/4001/p2p/" + me),
		"circuit only":        c("/p2p-circuit/p2p/" + me),
		"punycode relay host": c("/dns4/xn--80ak6aa92e.com/tcp/4001" + via),
	}
	for name, s := range cases {
		if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Parse(%q) = %v, want ErrInvalid", name, s, err)
		}
	}
}

// b32std is RFC 4648 base32, for building a hostile key string.
func b32std(b []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var out strings.Builder
	var buf, bits uint
	for _, c := range b {
		buf = buf<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			out.WriteByte(alpha[(buf>>(bits-5))&31])
			bits -= 5
		}
	}
	if bits > 0 {
		out.WriteByte(alpha[(buf<<(5-bits))&31])
	}
	return out.String()
}

func FuzzParse(f *testing.F) {
	k := testKey(f, 1)
	relay := peerID(f, 2)
	f.Add(Prefix + k.String())
	f.Add(Invite{Key: k, Handle: "a.example.com", Contact: "/dns4/r.example.net/tcp/1/p2p/" + relay + "/p2p-circuit"}.String())
	f.Add(Prefix + k.String() + "?c=/ip4/10.0.0.1/tcp/1")
	f.Add(Prefix + k.String() + "?h=xn--a.com&c=%2F")
	f.Add("openaim:add/?&=")
	f.Fuzz(func(t *testing.T, s string) {
		in, err := Parse(s)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q): error not ErrInvalid: %v", s, err)
			}
			return
		}
		// Whatever parses formats to a link that parses back the same,
		// within the limits, with a safe contact hint.
		out := in.String()
		if len(out) > MaxLen {
			t.Fatalf("formatted link of %d bytes", len(out))
		}
		again, err := Parse(out)
		if err != nil || again != in {
			t.Fatalf("round trip of %q: %+v %v, want %+v", out, again, err, in)
		}
		if _, err := identity.ParsePublicKey(in.Key[:]); err != nil {
			t.Fatalf("accepted bad key: %v", err)
		}
		if in.Contact != "" {
			if strings.HasPrefix(in.Contact, "/ip4/") || strings.HasPrefix(in.Contact, "/ip6/") {
				if !strings.Contains(in.Contact, "/p2p-circuit") {
					t.Fatalf("accepted a plain IP contact %q", in.Contact)
				}
			}
		}
	})
}
