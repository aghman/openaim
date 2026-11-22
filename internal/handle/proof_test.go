package handle

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var loopback = netip.MustParseAddr("127.0.0.1")

// proofServer serves h at ProofPath on loopback. Its certificate covers
// *.example.com, so handles under example.com pass TLS verification.
func proofServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	// Rejected handshakes are expected; keep them out of the test log.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// proofConfig points fetches at srv: every name resolves to loopback, the
// guard lets loopback through, and srv's certificate is trusted.
func proofConfig(t *testing.T, srv *httptest.Server) ProofConfig {
	t.Helper()
	port, err := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return ProofConfig{
		LookupIP:  func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{loopback}, nil },
		AllowAddr: func(a netip.Addr) bool { return a == loopback },
		Port:      uint16(port),
		RootCAs:   pool,
	}
}

func serveText(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ProofPath || r.Host != alice {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(body))
	}
}

func TestProofFallback(t *testing.T) {
	signer := id(t, 1)
	r := mustRecord(t, signer, alice, "/ip4/203.0.113.7/tcp/4001")
	srv := proofServer(t, serveText(r.String()+"\n"))

	// The DoH zone has no TXT record but does give the web server's
	// address, so this also covers the default DoH address lookup.
	z := zone(map[string][]dnsmessage.ResourceBody{
		"alice.example.com.": {&dnsmessage.AResource{A: loopback.As4()}},
	})
	v := verifier(dohServer(t, z), dohServer(t, z))
	v.Proof = proofConfig(t, srv)
	v.Proof.LookupIP = nil

	res, err := v.Verify(context.Background(), alice)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != SourceHTTPS || res.Key != signer.Public() || res.Inbox != r.Inbox {
		t.Fatalf("result %+v", res)
	}
}

func TestProofNotFound(t *testing.T) {
	srv := proofServer(t, http.NotFound)
	nx := zone(nil)
	v := verifier(dohServer(t, nx), dohServer(t, nx))
	v.Proof = proofConfig(t, srv)
	_, err := v.Verify(context.Background(), alice)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
	if pr := ComparePin(nil, err, id(t, 1).Public()); pr.Status != PinUnverified {
		t.Fatalf("pin %v", pr.Status)
	}
	// No addresses at all is a definite "no proof" too.
	v.Proof.LookupIP = nil
	if _, err := v.Verify(context.Background(), alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no addresses: got %v, want ErrNotFound", err)
	}
}

func TestProofRedirect(t *testing.T) {
	var followed atomic.Bool
	srv := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed.Store(true)
			w.Write([]byte(mustRecord(t, id(t, 1), alice, "").String()))
			return
		}
		http.Redirect(w, r, "https://"+alice+"/elsewhere", http.StatusFound)
	})
	v := &Verifier{Proof: proofConfig(t, srv)}
	if _, err := v.FetchProof(context.Background(), alice); !errors.Is(err, ErrRedirect) {
		t.Fatalf("got %v, want ErrRedirect", err)
	}
	if followed.Load() {
		t.Fatal("redirect was followed")
	}
}

func TestProofGuard(t *testing.T) {
	r := mustRecord(t, id(t, 1), alice, "")
	srv := proofServer(t, serveText(r.String()))
	ctx := context.Background()

	// The default guard refuses loopback, so the fetch never connects.
	v := &Verifier{Proof: proofConfig(t, srv)}
	v.Proof.AllowAddr = nil
	if _, err := v.FetchProof(ctx, alice); !errors.Is(err, ErrForbiddenAddr) {
		t.Fatalf("loopback with the default guard: %v", err)
	}

	// One forbidden address among good ones refuses the whole fetch.
	v = &Verifier{Proof: proofConfig(t, srv)}
	v.Proof.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{loopback, netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, err := v.FetchProof(ctx, alice); !errors.Is(err, ErrForbiddenAddr) {
		t.Fatalf("mixed addresses: %v", err)
	}

	// The guard also runs in the dialer on the address being connected
	// to. Here it says yes when the lookup is checked and no at connect
	// time, standing in for a rebinding answer.
	var calls atomic.Int32
	v = &Verifier{Proof: proofConfig(t, srv)}
	v.Proof.AllowAddr = func(netip.Addr) bool { return calls.Add(1) == 1 }
	_, err := v.FetchProof(ctx, alice)
	if !errors.Is(err, ErrForbiddenAddr) || calls.Load() < 2 {
		t.Fatalf("dial-time guard: %v after %d calls", err, calls.Load())
	}
	if pr := ComparePin(nil, err, r.Key); pr.Status != PinUnverified {
		t.Fatalf("pin %v", pr.Status)
	}

	// With loopback allowed, the same server is fine.
	v = &Verifier{Proof: proofConfig(t, srv)}
	if got, err := v.FetchProof(ctx, alice); err != nil || *got != *r {
		t.Fatalf("allowed fetch: %v", err)
	}
}

func TestProofOversize(t *testing.T) {
	pad := strings.Repeat("x", MaxProofSize+1)
	for name, h := range map[string]http.HandlerFunc{
		"content-length": serveText(pad),
		"chunked": func(w http.ResponseWriter, _ *http.Request) {
			for range 5 {
				w.Write([]byte(pad[:1024]))
				w.(http.Flusher).Flush()
			}
		},
	} {
		v := &Verifier{Proof: proofConfig(t, proofServer(t, h))}
		if _, err := v.FetchProof(context.Background(), alice); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: got %v, want ErrTooLarge", name, err)
		}
	}
}

func TestProofTLSAndTimeouts(t *testing.T) {
	r := mustRecord(t, id(t, 1), alice, "")
	srv := proofServer(t, serveText(r.String()))
	ctx := context.Background()

	// Without the test root, the certificate isn't trusted.
	v := &Verifier{Proof: proofConfig(t, srv)}
	v.Proof.RootCAs = nil
	if _, err := v.FetchProof(ctx, alice); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("untrusted cert: %v", err)
	}

	// The certificate covers *.example.com, not other names.
	v = &Verifier{Proof: proofConfig(t, srv)}
	if _, err := v.FetchProof(ctx, "alice.example.org"); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("wrong name: %v", err)
	}

	slow := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	v = &Verifier{Proof: proofConfig(t, slow)}
	v.Proof.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := v.FetchProof(ctx, alice); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("slow server: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %v", d)
	}

	for name, h := range map[string]http.HandlerFunc{
		"500":     func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
		"garbage": serveText("hello"),
	} {
		v := &Verifier{Proof: proofConfig(t, proofServer(t, h))}
		_, err := v.FetchProof(ctx, alice)
		if name == "500" && !errors.Is(err, ErrUnreachable) || name == "garbage" && !errors.Is(err, ErrRecord) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	public := []string{"1.1.1.1", "9.9.9.9", "93.184.216.34", "2606:4700:4700::1111", "2620:fe::fe",
		"64:ff9b::808:808", "2002:808:808::1"}
	private := []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "127.255.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.169.254", "100.64.0.1", "192.0.0.8", "192.0.2.1", "198.18.0.1",
		"198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::127.0.0.1", "fe80::1", "fe80::1%en0",
		"fc00::1", "fd12:3456::1", "ff02::1", "ff05::2", "fec0::1", "2001:db8::1", "3fff::1",
		"2001::1", "100::1", "64:ff9b::7f00:1", "64:ff9b:1::1", "2002:7f00:1::1", "2002:a00:1::1",
	}
	for _, s := range public {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("PublicAddr(%s) = false", s)
		}
	}
	for _, s := range private {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("PublicAddr(%s) = true", s)
		}
	}
	if PublicAddr(netip.Addr{}) {
		t.Error("zero Addr is public")
	}
}
