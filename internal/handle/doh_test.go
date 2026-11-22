package handle

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// answerFunc plays a DNS zone for a fake DoH resolver.
type answerFunc func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource)

// dohServer is an RFC 8484 resolver on loopback. All httptest TLS servers
// share one certificate, so any server's Client trusts every one of them.
func dohServer(t *testing.T, answer answerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != dnsMessageType {
			http.Error(w, "want an RFC 8484 POST", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var m dnsmessage.Message
		if err := m.Unpack(body); err != nil || len(m.Questions) != 1 || m.ID != 0 || !m.RecursionDesired {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		rcode, ans := answer(m.Questions[0])
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode},
			Questions: m.Questions,
			Answers:   ans,
		}
		b, err := resp.Pack()
		if err != nil {
			t.Errorf("pack: %v", err)
		}
		w.Header().Set("Content-Type", dnsMessageType)
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func rr(name string, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: 300},
		Body:   body,
	}
}

// zone answers from a fixed map of owner name to records, NXDOMAIN for
// names it doesn't hold, and an empty answer for other types.
func zone(records map[string][]dnsmessage.ResourceBody) answerFunc {
	return func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		name := strings.ToLower(q.Name.String())
		bodies, ok := records[name]
		if !ok {
			return dnsmessage.RCodeNameError, nil
		}
		var out []dnsmessage.Resource
		for _, b := range bodies {
			if t := bodyType(b); t == q.Type || t == dnsmessage.TypeCNAME {
				out = append(out, rr(name, b))
			}
		}
		return dnsmessage.RCodeSuccess, out
	}
}

func bodyType(b dnsmessage.ResourceBody) dnsmessage.Type {
	switch b.(type) {
	case *dnsmessage.TXTResource:
		return dnsmessage.TypeTXT
	case *dnsmessage.AResource:
		return dnsmessage.TypeA
	case *dnsmessage.AAAAResource:
		return dnsmessage.TypeAAAA
	case *dnsmessage.CNAMEResource:
		return dnsmessage.TypeCNAME
	}
	return 0
}

func txt(strs ...string) *dnsmessage.TXTResource { return &dnsmessage.TXTResource{TXT: strs} }

func recordZone(name string, r *Record) answerFunc {
	return zone(map[string][]dnsmessage.ResourceBody{name: {txt(r.TXTStrings()...)}})
}

func verifier(a, b *httptest.Server) *Verifier {
	return &Verifier{Resolvers: []string{a.URL, b.URL}, Client: a.Client()}
}

const alice = "alice.example.com"
const aliceTXT = "_openaim.alice.example.com."

func TestVerifyDNS(t *testing.T) {
	signer := id(t, 1)
	long := "/dns/inbox.example.com/tcp/4001/p2p/" + strings.Repeat("x", 300) // forces several TXT strings
	r := mustRecord(t, signer, alice, long)
	if len(r.TXTStrings()) < 2 {
		t.Fatal("test setup: want a multi-string record")
	}
	z := zone(map[string][]dnsmessage.ResourceBody{
		aliceTXT: {txt("google-site-verification=abc"), txt(r.TXTStrings()...), txt("v=oa2; future")},
	})
	v := verifier(dohServer(t, z), dohServer(t, z))
	v.Proof.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
		t.Error("HTTPS proof fetched although DNS had a record")
		return nil, ErrNotFound
	}
	res, err := v.Verify(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if res.Key != signer.Public() || res.Inbox != long || !res.Issued.Equal(issued) || res.Source != SourceDNS || res.Handle != alice {
		t.Fatalf("result %+v", res)
	}
	if pr := v.CheckPin(context.Background(), alice, signer.Public()); pr.Status != PinVerified {
		t.Fatalf("pin check: %v %v", pr.Status, pr.Err)
	}
}

func TestVerifyCNAME(t *testing.T) {
	r := mustRecord(t, id(t, 1), alice, "")
	target := "alice.handles.registry.example."
	z := zone(map[string][]dnsmessage.ResourceBody{
		aliceTXT: {&dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}},
	})
	// The resolver chases the CNAME and puts both in the answer.
	chased := func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		rc, ans := z(q)
		return rc, append(ans, rr(target, txt(r.String())))
	}
	v := verifier(dohServer(t, chased), dohServer(t, chased))
	if res, err := v.Verify(context.Background(), alice); err != nil || res.Key != r.Key {
		t.Fatalf("verify via CNAME: %v", err)
	}
}

func TestVerifyWrongHandle(t *testing.T) {
	// A record Bob signed for his own handle, copied into Alice's zone.
	r := mustRecord(t, id(t, 2), "bob.example.com", "")
	z := recordZone(aliceTXT, r)
	v := verifier(dohServer(t, z), dohServer(t, z))
	if _, err := v.Verify(context.Background(), alice); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v, want ErrSignature", err)
	}
}

func TestVerifyMoved(t *testing.T) {
	pinned, thief := id(t, 1), id(t, 3)
	z := recordZone(aliceTXT, mustRecord(t, thief, alice, ""))
	v := verifier(dohServer(t, z), dohServer(t, z))
	pr := v.CheckPin(context.Background(), alice, pinned.Public())
	if pr.Status != PinMoved || pr.Result == nil || pr.Result.Key != thief.Public() {
		t.Fatalf("got %v %+v %v, want moved", pr.Status, pr.Result, pr.Err)
	}
}

func TestResolversDisagree(t *testing.T) {
	signer := id(t, 1)
	r1 := mustRecord(t, signer, alice, "")
	r2, err := NewRecord(signer, alice, issued.Add(time.Second), "") // validly signed, but different
	if err != nil {
		t.Fatal(err)
	}
	nx := zone(nil)
	for name, zs := range map[string][2]answerFunc{
		"different records": {recordZone(aliceTXT, r1), recordZone(aliceTXT, r2)},
		"one hides it":      {recordZone(aliceTXT, r1), nx},
		"other hides it":    {nx, recordZone(aliceTXT, r1)},
	} {
		v := verifier(dohServer(t, zs[0]), dohServer(t, zs[1]))
		_, err := v.Verify(context.Background(), alice)
		if !errors.Is(err, ErrDisagree) {
			t.Errorf("%s: got %v, want ErrDisagree", name, err)
		}
		if pr := ComparePin(nil, err, signer.Public()); pr.Status != PinUnreachable {
			t.Errorf("%s: pin %v", name, pr.Status)
		}
	}
}

func TestResolverDown(t *testing.T) {
	signer := id(t, 1)
	good := dohServer(t, recordZone(aliceTXT, mustRecord(t, signer, alice, "")))
	broken := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer broken.Close()
	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closed.Close()
	servfail := dohServer(t, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		return dnsmessage.RCodeServerFailure, nil
	})
	wrongType := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>captive portal</html>"))
	}))
	defer wrongType.Close()

	for name, other := range map[string]string{
		"503": broken.URL, "closed": closed.URL, "servfail": servfail.URL, "content type": wrongType.URL,
	} {
		v := &Verifier{Resolvers: []string{good.URL, other}, Client: good.Client()}
		v.Proof.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
			t.Errorf("%s: fell back to the HTTPS proof", name)
			return nil, ErrNotFound
		}
		_, err := v.Verify(context.Background(), alice)
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: got %v, want ErrUnreachable", name, err)
		}
		if pr := v.CheckPin(context.Background(), alice, signer.Public()); pr.Status != PinUnreachable {
			t.Errorf("%s: pin %v", name, pr.Status)
		}
	}
}

func TestDoHOversize(t *testing.T) {
	r := mustRecord(t, id(t, 1), alice, "")
	var junk []dnsmessage.ResourceBody
	for range 80 {
		junk = append(junk, txt(strings.Repeat("j", 250)))
	}
	big := zone(map[string][]dnsmessage.ResourceBody{aliceTXT: append(junk, txt(r.String()))})
	v := verifier(dohServer(t, big), dohServer(t, recordZone(aliceTXT, r)))
	_, err := v.Verify(context.Background(), alice)
	if !errors.Is(err, ErrTooLarge) || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrTooLarge and ErrUnreachable", err)
	}
}

func TestAmbiguous(t *testing.T) {
	signer := id(t, 1)
	r1 := mustRecord(t, signer, alice, "")
	r2 := mustRecord(t, signer, alice, "/ip4/203.0.113.7/tcp/4001")
	z := zone(map[string][]dnsmessage.ResourceBody{aliceTXT: {txt(r1.String()), txt(r2.String())}})
	v := verifier(dohServer(t, z), dohServer(t, z))
	if _, err := v.Verify(context.Background(), alice); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("got %v, want ErrAmbiguous", err)
	}
}

func TestMalformedDNSRecord(t *testing.T) {
	z := zone(map[string][]dnsmessage.ResourceBody{aliceTXT: {txt("v=oa1; k=nope")}})
	v := verifier(dohServer(t, z), dohServer(t, z))
	if _, err := v.Verify(context.Background(), alice); !errors.Is(err, ErrRecord) {
		t.Fatalf("got %v, want ErrRecord", err)
	}
}

func TestVerifyRejectsBadHandle(t *testing.T) {
	var queried atomic.Bool
	z := func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		queried.Store(true)
		return dnsmessage.RCodeNameError, nil
	}
	v := verifier(dohServer(t, z), dohServer(t, z))
	for _, h := range []string{"xn--80ak6aa92e.com", "Alice.example.com", "a_b.example.com", "com"} {
		if _, err := v.Verify(context.Background(), h); !errors.Is(err, ErrSyntax) {
			t.Errorf("Verify(%q) = %v, want ErrSyntax", h, err)
		}
	}
	if queried.Load() {
		t.Fatal("a bad handle reached the resolver")
	}
}

func TestResolverConfig(t *testing.T) {
	ctx := context.Background()
	for name, rs := range map[string][]string{
		"one":       {"https://a.example/dns-query"},
		"plain":     {"https://a.example/dns-query", "http://b.example/dns-query"},
		"duplicate": {"https://a.example/dns-query", "https://a.example/dns-query"},
		"empty":     {},
	} {
		v := &Verifier{Resolvers: rs}
		if _, err := v.Verify(ctx, alice); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: got %v, want ErrConfig", name, err)
		}
	}
	if rs, err := (&Verifier{}).resolvers(); err != nil || len(rs) != 2 {
		t.Fatalf("defaults: %v %v", rs, err)
	}
}

func packResponse(t testing.TB, h dnsmessage.Header, q []dnsmessage.Question, ans ...dnsmessage.Resource) []byte {
	t.Helper()
	b, err := (&dnsmessage.Message{Header: h, Questions: q, Answers: ans}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAnswer(t *testing.T) {
	q := []dnsmessage.Question{{Name: dnsmessage.MustNewName(aliceTXT), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}
	ok := dnsmessage.Header{Response: true}
	ans := rr(aliceTXT, txt("v=oa1; x"))
	if got, err := txtCandidates(packResponse(t, ok, q, ans), aliceTXT); err != nil || len(got) != 1 {
		t.Fatalf("good response: %v %v", got, err)
	}
	// Owner names compare case-insensitively.
	upper := rr(strings.ToUpper(aliceTXT), txt("v=oa1; x"))
	if _, err := txtCandidates(packResponse(t, ok, q, upper), aliceTXT); err != nil {
		t.Fatalf("uppercase owner: %v", err)
	}

	otherQ := []dnsmessage.Question{{Name: dnsmessage.MustNewName("_openaim.bob.example.com."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}
	aQ := []dnsmessage.Question{{Name: q[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}
	loop := []dnsmessage.Resource{
		rr(aliceTXT, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("x.example.")}),
		rr("x.example.", &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(aliceTXT)}),
	}
	for name, c := range map[string]struct {
		msg  []byte
		want error
	}{
		"not a response":   {packResponse(t, dnsmessage.Header{}, q, ans), errBadResponse},
		"wrong id":         {packResponse(t, dnsmessage.Header{Response: true, ID: 7}, q, ans), errBadResponse},
		"truncated":        {packResponse(t, dnsmessage.Header{Response: true, Truncated: true}, q, ans), errBadResponse},
		"other question":   {packResponse(t, ok, otherQ, ans), errBadResponse},
		"other type":       {packResponse(t, ok, aQ, ans), errBadResponse},
		"no question":      {packResponse(t, ok, nil, ans), errBadResponse},
		"garbage":          {[]byte{1, 2, 3}, errBadResponse},
		"nxdomain":         {packResponse(t, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError}, q), ErrNotFound},
		"refused":          {packResponse(t, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeRefused}, q), ErrUnreachable},
		"empty answer":     {packResponse(t, ok, q), ErrNotFound},
		"answer elsewhere": {packResponse(t, ok, q, rr("other.example.", txt("v=oa1; x"))), ErrNotFound},
		"no v1 record":     {packResponse(t, ok, q, rr(aliceTXT, txt("v=spf1 -all"))), ErrNotFound},
		"cname loop":       {packResponse(t, ok, q, loop...), ErrNotFound},
	} {
		if _, err := txtCandidates(c.msg, aliceTXT); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func FuzzParseAnswer(f *testing.F) {
	q := []dnsmessage.Question{{Name: dnsmessage.MustNewName(aliceTXT), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}
	ok := dnsmessage.Header{Response: true}
	r := mustRecord(f, id(f, 1), alice, strings.Repeat("p", 300))
	f.Add(packResponse(f, ok, q, rr(aliceTXT, txt(r.TXTStrings()...))))
	f.Add(packResponse(f, ok, q,
		rr(aliceTXT, &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("x.example.")}),
		rr("x.example.", txt("v=oa1; k=x"))))
	f.Add(packResponse(f, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError}, q))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		texts, err := txtCandidates(msg, aliceTXT)
		if err == nil {
			for _, s := range texts {
				if !isCandidate(s) {
					t.Fatalf("non-candidate %q returned", s)
				}
				_, _ = ParseRecord(s)
			}
		} else if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrUnreachable) {
			t.Fatalf("unclassified error: %v", err)
		}
		// The address path shares the parser.
		_, _ = parseAnswer(msg, "alice.example.com.", dnsmessage.TypeA)
	})
}
