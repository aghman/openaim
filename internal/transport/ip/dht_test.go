package ip

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func newRdvKey(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustSign(t testing.TB, priv ed25519.PrivateKey, seq uint64, payload []byte) []byte {
	t.Helper()
	v, err := SignRendezvousRecord(priv, seq, payload)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRendezvousRecordRoundTrip(t *testing.T) {
	priv := newRdvKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	key := RendezvousKey(pub)
	if !strings.HasPrefix(key, "/oa-rdv/") || len(key) != len("/oa-rdv/")+64 {
		t.Fatalf("key %q", key)
	}
	for _, n := range []int{1, 200, MaxRendezvousPayload} {
		payload := bytes.Repeat([]byte{0xC3}, n)
		v := mustSign(t, priv, 1234, payload)
		if len(v) > MaxRendezvousValue {
			t.Fatalf("%d-byte payload gives a %d-byte value", n, len(v))
		}
		r, err := ParseRendezvousRecord(key, v)
		if err != nil {
			t.Fatal(err)
		}
		if r.Seq != 1234 || !r.PublicKey.Equal(pub) || !bytes.Equal(r.Payload, payload) {
			t.Errorf("parsed %+v", r)
		}
		if err := (RendezvousValidator{}).Validate(key, v); err != nil {
			t.Error(err)
		}
		if err := DHTValidator().Validate(key, v); err != nil {
			t.Errorf("namespaced: %v", err)
		}
	}
	for _, n := range []int{0, MaxRendezvousPayload + 1} {
		if _, err := SignRendezvousRecord(priv, 1, make([]byte, n)); !errors.Is(err, ErrBadRendezvousRecord) {
			t.Errorf("%d-byte payload: %v", n, err)
		}
	}
}

func TestRendezvousValidatorRejects(t *testing.T) {
	priv, other := newRdvKey(t), newRdvKey(t)
	key := RendezvousKey(priv.Public().(ed25519.PublicKey))
	good := mustSign(t, priv, 7, []byte("ciphertext"))
	mutate := func(f func(v []byte) []byte) []byte { return f(slices.Clone(good)) }
	oversize := mustSign(t, priv, 7, make([]byte, MaxRendezvousPayload))
	oversize = append(oversize[:len(oversize)-64], append([]byte{0}, oversize[len(oversize)-64:]...)...)

	cases := map[string]struct {
		key   string
		value []byte
	}{
		"empty":              {key, nil},
		"too short":          {key, good[:rdvHeaderLen+ed25519.SignatureSize]},
		"oversize":           {key, oversize},
		"bad version":        {key, mutate(func(v []byte) []byte { v[0] = 2; return v })},
		"seq changed":        {key, mutate(func(v []byte) []byte { v[8] ^= 1; return v })},
		"payload changed":    {key, mutate(func(v []byte) []byte { v[rdvHeaderLen] ^= 1; return v })},
		"bad signature":      {key, mutate(func(v []byte) []byte { v[len(v)-1] ^= 1; return v })},
		"truncated":          {key, good[:len(good)-1]},
		"other key's record": {key, mustSign(t, other, 7, []byte("ciphertext"))},
		"key uppercase":      {strings.ToUpper(key[:8]) + strings.ToUpper(key[8:]), good},
		"key hex uppercase":  {key[:8] + strings.ToUpper(key[8:]), good},
		"key short":          {key[:len(key)-2], good},
		"key not hex":        {key[:len(key)-1] + "g", good},
		"key namespace":      {"/pk/" + key[8:], good},
		"key no namespace":   {key[8:], good},
	}
	for name, c := range cases {
		if err := (RendezvousValidator{}).Validate(c.key, c.value); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := DHTValidator().Validate(c.key, c.value); err == nil {
			t.Errorf("%s: namespaced validator accepted", name)
		}
	}
}

func TestRendezvousValidatorSelect(t *testing.T) {
	priv := newRdvKey(t)
	key := RendezvousKey(priv.Public().(ed25519.PublicKey))
	v1 := mustSign(t, priv, 1, []byte("old"))
	v2 := mustSign(t, priv, 2, []byte("new"))
	v2b := mustSign(t, priv, 2, []byte("new, other payload"))
	forged := mustSign(t, newRdvKey(t), 99, []byte("forged")) // valid elsewhere, not here
	junk := []byte("junk")
	var val RendezvousValidator

	pick := func(vals ...[]byte) []byte {
		t.Helper()
		i, err := val.Select(key, vals)
		if err != nil {
			t.Fatal(err)
		}
		return vals[i]
	}
	if got := pick(v1, v2); !bytes.Equal(got, v2) {
		t.Error("newer seq not chosen")
	}
	if got := pick(v2, v1); !bytes.Equal(got, v2) {
		t.Error("newer seq not chosen (reversed)")
	}
	if got := pick(junk, forged, v1); !bytes.Equal(got, v1) {
		t.Error("invalid value chosen over a valid one")
	}
	// Equal seqs: the same winner whatever the order.
	a, b := pick(v2, v2b), pick(v2b, v2)
	if !bytes.Equal(a, b) {
		t.Error("tie-break depends on order")
	}
	if _, err := val.Select(key, [][]byte{junk, forged}); err == nil {
		t.Error("Select picked from no valid values")
	}
	if _, err := DHTValidator().Select(key, nil); err == nil {
		t.Error("Select picked from nothing")
	}
}

func FuzzRendezvousRecord(f *testing.F) {
	priv := newRdvKey(f)
	key := RendezvousKey(priv.Public().(ed25519.PublicKey))
	good := mustSign(f, priv, 5, []byte("payload"))
	f.Add(key, good)
	f.Add(key, good[:50])
	f.Add("/oa-rdv/00", []byte{1})
	f.Fuzz(func(t *testing.T, key string, value []byte) {
		r, err := ParseRendezvousRecord(key, value)
		if err != nil {
			if !errors.Is(err, ErrBadRendezvousRecord) {
				t.Fatalf("unwrapped error %v", err)
			}
			return
		}
		if len(value) > MaxRendezvousValue || len(r.Payload) == 0 || RendezvousKey(r.PublicKey) != key {
			t.Fatalf("accepted bad record: %d bytes, payload %d", len(value), len(r.Payload))
		}
		i, err := (RendezvousValidator{}).Select(key, [][]byte{[]byte("x"), value})
		if err != nil || i != 1 {
			t.Fatalf("Select = %d, %v", i, err)
		}
	})
}

func TestNetworkConfigDefaults(t *testing.T) {
	c := DefaultNetworkConfig()
	if c.Bootstrap == nil || c.Relays == nil {
		t.Fatal("default lists are nil")
	}
	if len(c.Bootstrap) != 0 || len(c.Relays) != 0 {
		t.Errorf("defaults list nodes we don't operate: %+v", c)
	}
	if !bytes.Contains(DefaultNetworkConfigJSON(), []byte("NO COMMUNITY NODES ARE OPERATED YET")) {
		t.Error("default config does not say that no nodes are operated")
	}
	got, err := LoadNetworkConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || len(got.Bootstrap) != 0 {
		t.Errorf("missing file: %+v, %v", got, err)
	}
}

func TestNetworkConfigParse(t *testing.T) {
	id1, id2 := testPeerID(t), testPeerID(t)
	a1 := "/ip4/192.0.2.1/tcp/4001/p2p/" + id1.String()
	a1q := "/ip4/192.0.2.1/udp/4001/quic-v1/p2p/" + id1.String()
	a2 := "/dns4/boot.example.org/tcp/4001/p2p/" + id2.String()

	c, err := ParseNetworkConfig([]byte(`{"bootstrap": ["` + a1 + `", "` + a2 + `", "` + a1q + `", "` + a1 + `"], "relays": ["` + a2 + `"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Bootstrap) != 2 || c.Bootstrap[0].ID != id1 || c.Bootstrap[1].ID != id2 {
		t.Fatalf("bootstrap = %v", c.Bootstrap)
	}
	if len(c.Bootstrap[0].Addrs) != 2 {
		t.Errorf("addresses of one peer not merged and deduplicated: %v", c.Bootstrap[0].Addrs)
	}
	if len(c.Relays) != 1 || c.Relays[0].ID != id2 {
		t.Errorf("relays = %v", c.Relays)
	}

	// Override: a list that is set replaces the default; one left out keeps it.
	c, err = ParseNetworkConfig([]byte(`{"comment": "mine", "relays": ["` + a2 + `"]}`))
	if err != nil || len(c.Bootstrap) != len(DefaultNetworkConfig().Bootstrap) || len(c.Relays) != 1 {
		t.Errorf("partial override: %+v, %v", c, err)
	}
	c, err = parseNetworkConfig([]byte(`{"bootstrap": []}`), NetworkConfig{Bootstrap: []peer.AddrInfo{{ID: id1}}, Relays: []peer.AddrInfo{{ID: id2}}})
	if err != nil || len(c.Bootstrap) != 0 || len(c.Relays) != 1 {
		t.Errorf("empty list should clear only that list: %+v, %v", c, err)
	}

	path := filepath.Join(t.TempDir(), "network.json")
	if err := os.WriteFile(path, []byte(`{"bootstrap": ["`+a2+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadNetworkConfig(path); err != nil || len(c.Bootstrap) != 1 {
		t.Errorf("load: %+v, %v", c, err)
	}
	// The embedded template parses as a user file too.
	if _, err := ParseNetworkConfig(DefaultNetworkConfigJSON()); err != nil {
		t.Error(err)
	}

	many := `{"bootstrap": [` + strings.TrimSuffix(strings.Repeat(`"`+a1+`",`, MaxNetworkConfigList+1), ",") + `]}`
	bad := map[string]string{
		"not json":       `{`,
		"unknown field":  `{"bootstrapp": []}`,
		"trailing data":  `{} {}`,
		"wrong type":     `{"bootstrap": "` + a1 + `"}`,
		"bad multiaddr":  `{"bootstrap": ["/ip4/nope"]}`,
		"no peer ID":     `{"bootstrap": ["/ip4/192.0.2.1/tcp/4001"]}`,
		"no address":     `{"bootstrap": ["/p2p/` + id1.String() + `"]}`,
		"circuit":        `{"relays": ["/ip4/192.0.2.1/tcp/4001/p2p/` + id2.String() + `/p2p-circuit/p2p/` + id1.String() + `"]}`,
		"too many":       many,
		"too big":        `{"comment": "` + strings.Repeat("x", MaxNetworkConfigSize) + `"}`,
		"top-level list": `[]`,
	}
	for name, s := range bad {
		if c, err := ParseNetworkConfig([]byte(s)); err == nil {
			t.Errorf("%s: accepted: %+v", name, c)
		}
	}
}

func FuzzParseNetworkConfig(f *testing.F) {
	f.Add(DefaultNetworkConfigJSON())
	f.Add([]byte(`{"bootstrap": ["/ip4/192.0.2.1/tcp/4001/p2p/12D3KooWGzvjjNnLi8PCgTUXhbF6XZr9YN1B8Yzyg9xd3ZfEuG8q"]}`))
	f.Add([]byte(`{"relays": null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseNetworkConfig(b)
		if err != nil {
			return
		}
		for _, l := range [][]peer.AddrInfo{c.Bootstrap, c.Relays} {
			if len(l) > MaxNetworkConfigList {
				t.Fatalf("%d entries", len(l))
			}
			for _, ai := range l {
				if ai.ID == "" || len(ai.Addrs) == 0 {
					t.Fatalf("entry without ID or address: %v", ai)
				}
			}
		}
	})
}

func testPeerID(t *testing.T) peer.ID {
	t.Helper()
	n := newTestHost(t)
	return n.ID()
}

// dhtNode is a Node running the DHT.
type dhtNode struct {
	*Node
	dht *DHT
}

func newDHTNode(t *testing.T, mode DHTMode, boot []peer.AddrInfo, o NodeOptions) *dhtNode {
	t.Helper()
	if o.Interval == 0 {
		o.Interval = -1
	}
	n := newTestNode(t, o)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	d, err := NewDHT(ctx, n, DHTOptions{Mode: mode, Bootstrap: boot, BootstrapTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return &dhtNode{n, d}
}

// p2pInfo is n's current peer ID and its loopback address.
func (n *dhtNode) p2pInfo() peer.AddrInfo {
	return peer.AddrInfo{ID: n.ID(), Addrs: n.Host().Addrs()}
}

func (n *dhtNode) rtSize(t *testing.T) int {
	kd, err := n.dht.Instance()
	if err != nil {
		t.Fatal(err)
	}
	return kd.RoutingTable().Size()
}

func put(t *testing.T, n *dhtNode, priv ed25519.PrivateKey, seq uint64, payload string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key, err := n.dht.PutRendezvous(ctx, priv, seq, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func get(t *testing.T, n *dhtNode, key string) RendezvousRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := n.dht.GetRendezvous(ctx, key)
	if err != nil {
		t.Fatalf("get from %s: %v", n.ID(), err)
	}
	return r
}

func hasProtocol(n *dhtNode, p protocol.ID) bool {
	return slices.Contains(n.Host().Mux().Protocols(), p)
}

// TestDHTThreeNodes is the ticket's acceptance test: three local nodes form
// the private DHT from a bootstrap list loaded from config, and store and
// find rendezvous records.
func TestDHTThreeNodes(t *testing.T) {
	a := newDHTNode(t, DHTServer, nil, NodeOptions{})
	addrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: a.ID(), Addrs: a.Host().Addrs()})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseNetworkConfig([]byte(`{"bootstrap": ["` + addrs[0].String() + `"]}`))
	if err != nil {
		t.Fatal(err)
	}
	b := newDHTNode(t, DHTServer, cfg.Bootstrap, NodeOptions{})
	c := newDHTNode(t, DHTClient, cfg.Bootstrap, NodeOptions{})

	if !hasProtocol(a, DHTProtocol) || hasProtocol(a, "/ipfs/kad/1.0.0") {
		t.Errorf("server protocols = %v, want %s only", a.Host().Mux().Protocols(), DHTProtocol)
	}
	if hasProtocol(c, DHTProtocol) {
		t.Error("client serves the DHT")
	}
	// B and C found A by bootstrapping; A learned B (a server) back.
	waitFor(t, func() bool { return a.rtSize(t) == 1 && b.rtSize(t) >= 1 && c.rtSize(t) == 2 })

	privB, privC := newRdvKey(t), newRdvKey(t)
	kb := put(t, b, privB, 1, "from B")
	kc := put(t, c, privC, 1, "from C") // a client can publish
	if r := get(t, c, kb); string(r.Payload) != "from B" {
		t.Errorf("C got %q", r.Payload)
	}
	if r := get(t, b, kc); string(r.Payload) != "from C" {
		t.Errorf("B got %q", r.Payload)
	}

	// A newer record replaces the old one everywhere; an older one does not.
	put(t, c, privB, 5, "B, newer") // anyone holding the key may publish
	if r := get(t, a, kb); r.Seq != 5 {
		t.Errorf("A has seq %d, want 5", r.Seq)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.dht.PutRendezvous(ctx, privB, 3, []byte("B, older")); err == nil {
		t.Error("C replaced a newer record with an older one")
	}
	if r := get(t, b, kb); r.Seq != 5 || string(r.Payload) != "B, newer" {
		t.Errorf("B has %d %q, want the seq 5 record", r.Seq, r.Payload)
	}

	// Values outside the namespace or failing validation are refused.
	if err := c.dht.PutValue(ctx, "/pk/whatever", []byte("x")); err == nil {
		t.Error("put outside the rendezvous namespace accepted")
	}
	if err := c.dht.PutValue(ctx, kb, []byte("junk")); err == nil {
		t.Error("junk value accepted")
	}
}

// TestDHTSurvivesRotation: after a rotation the node runs a fresh DHT
// instance on its new host, bootstrapped from config, and can still publish
// and find records; the old instance closes with the old host.
func TestDHTSurvivesRotation(t *testing.T) {
	a := newDHTNode(t, DHTServer, nil, NodeOptions{})
	boot := []peer.AddrInfo{a.p2pInfo()}
	clk := newFakeClock()
	b := newDHTNode(t, DHTServer, boot, NodeOptions{Grace: time.Minute, Clock: clk})
	c := newDHTNode(t, DHTServer, boot, NodeOptions{})
	waitFor(t, func() bool { return a.rtSize(t) == 2 })

	privC := newRdvKey(t)
	kc := put(t, c, privC, 1, "before rotation")
	oldKD, _ := b.dht.Instance()
	oldID := b.ID()

	rotate(t, b.Node)
	newKD, err := b.dht.Instance()
	if err != nil {
		t.Fatal(err)
	}
	if newKD == oldKD || newKD.Host().ID() != b.ID() || b.ID() == oldID {
		t.Fatal("DHT did not move to the new host")
	}
	// Bootstrapped before the host became current, from config only.
	if n := newKD.RoutingTable().Size(); n == 0 {
		t.Fatal("new DHT instance has an empty routing table")
	}
	if slices.Contains(newKD.RoutingTable().ListPeers(), oldID) {
		t.Error("new instance knows the old peer ID")
	}

	if r := get(t, b, kc); string(r.Payload) != "before rotation" {
		t.Errorf("B after rotation got %q", r.Payload)
	}
	privB := newRdvKey(t)
	kb := put(t, b, privB, 1, "after rotation")
	if r := get(t, c, kb); string(r.Payload) != "after rotation" {
		t.Errorf("C got %q", r.Payload)
	}

	// The old instance goes with the old host.
	clk.waitTimer(t, time.Minute)
	clk.Advance(time.Minute)
	waitFor(t, func() bool { return len(b.LiveHosts()) == 1 })
	if oldKD.Context().Err() == nil {
		t.Error("old DHT instance still running after the grace period")
	}
	waitFor(t, func() bool { return !slices.Contains(a.Host().Network().Peers(), oldID) })
	if r := get(t, b, kb); string(r.Payload) != "after rotation" {
		t.Errorf("B after grace got %q", r.Payload)
	}

	if err := b.dht.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.dht.Instance(); err == nil {
		t.Error("DHT instance still there after Close")
	}
	if newKD.Context().Err() == nil {
		t.Error("DHT instance running after Close")
	}
}
