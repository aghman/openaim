package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc/codes"

	pb "github.com/aghman/openaim/internal/apipb"
	"github.com/aghman/openaim/internal/daemon"
	"github.com/aghman/openaim/internal/handle"
	"github.com/aghman/openaim/internal/identity"
)

// zone is a fake _openaim TXT zone served by two DoH resolvers on loopback.
type zone struct {
	t       *testing.T
	mu      sync.Mutex
	records map[string]*handle.Record
	a, b    *httptest.Server
}

func newZone(t *testing.T) *zone {
	z := &zone{t: t, records: map[string]*handle.Record{}}
	z.a, z.b = httptest.NewTLSServer(z), httptest.NewTLSServer(z)
	t.Cleanup(z.a.Close)
	t.Cleanup(z.b.Close)
	return z
}

func (z *zone) set(h string, signer *identity.Identity) {
	z.t.Helper()
	r, err := handle.NewRecord(signer, h, time.Unix(1767225600, 0), "/dns/inbox.example.com/tcp/4001")
	if err != nil {
		z.t.Fatal(err)
	}
	z.mu.Lock()
	z.records[h] = r
	z.mu.Unlock()
}

func (z *zone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var q dnsmessage.Message
	if err := q.Unpack(body); err != nil || len(q.Questions) != 1 {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	qq := q.Questions[0]
	resp := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RecursionDesired: true, RCode: dnsmessage.RCodeNameError}, Questions: q.Questions}
	name := strings.ToLower(qq.Name.String())
	z.mu.Lock()
	rec, ok := z.records[strings.TrimSuffix(strings.TrimPrefix(name, "_openaim."), ".")]
	z.mu.Unlock()
	if ok && qq.Type == dnsmessage.TypeTXT && strings.HasPrefix(name, "_openaim.") {
		resp.RCode = dnsmessage.RCodeSuccess
		resp.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.TXTResource{TXT: rec.TXTStrings()},
		}}
	}
	b, _ := resp.Pack()
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(b)
}

func (z *zone) verifier() *handle.Verifier {
	return &handle.Verifier{
		Resolvers: []string{z.a.URL, z.b.URL},
		Client:    z.a.Client(),
		Proof: handle.ProofConfig{LookupIP: func(context.Context, string) ([]netip.Addr, error) {
			return nil, handle.ErrNotFound
		}},
	}
}

func TestHandleRPCs(t *testing.T) {
	dir, _ := initDir(t)
	z := newZone(t)
	bob, carol := peer(t, 2), peer(t, 3)
	z.set("bob.example.com", bob)

	conf := cfg(dir)
	conf.HandleVerifier, conf.HandleRegistry = z.verifier(), "example.com"
	d, err := Start(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	conn, err := Dial(d.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	c := pb.NewDaemonClient(conn)
	ctx := ctxT(t)

	s, err := c.SubscribeEvents(ctx, &pb.SubscribeEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	recv(t, s) // ready

	// By handle: verified and pinned, shown short.
	b, err := c.AddBuddy(ctx, &pb.AddBuddyRequest{Handle: "@Bob.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if b.GetIdentityKey() != bob.Public().String() || b.GetHandle() != "bob.example.com" || b.GetShortHandle() != "bob" ||
		b.GetDisplayName() != "bob" || b.GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_VERIFIED ||
		b.GetHandleCheckedAt() == nil || b.GetHandleNextCheckAt() == nil || b.GetHandleError() != "" {
		t.Fatalf("added %v", b)
	}
	if e := recv(t, s); e.GetBuddyAdded().GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_VERIFIED {
		t.Fatalf("event %v", e)
	}

	// By key with someone else's handle: added, handle dropped, reason given.
	b, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{IdentityKey: carol.Public().String(), Handle: "bob.example.com", Petname: "Carol"})
	if err != nil {
		t.Fatal(err)
	}
	if b.GetHandle() != "" || !strings.Contains(b.GetHandleError(), "different key") || b.GetDisplayName() != "Carol" ||
		b.GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_UNSPECIFIED {
		t.Fatalf("claimed %v", b)
	}
	recv(t, s)

	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{Handle: "nobody.example.com"})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = c.AddBuddy(ctx, &pb.AddBuddyRequest{Handle: "not a handle"})
	wantCode(t, err, codes.InvalidArgument)
	_, err = c.CheckHandle(ctx, &pb.CheckHandleRequest{Buddy: "Carol"})
	wantCode(t, err, codes.FailedPrecondition)

	// The handle moves: CheckHandle reports it, warns, and keeps the pin.
	z.set("bob.example.com", carol)
	r, err := c.CheckHandle(ctx, &pb.CheckHandleRequest{Buddy: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if r.GetResult() != pb.HandleStatus_HANDLE_STATUS_MOVED || r.GetBuddy().GetIdentityKey() != bob.Public().String() ||
		r.GetBuddy().GetHandleMovedTo() != carol.Public().String() || r.GetBuddy().GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_MOVED {
		t.Fatalf("check %v", r)
	}
	if e := recv(t, s); e.GetBuddyChanged().GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_MOVED {
		t.Fatalf("event %v", e)
	}
	if e := recv(t, s); e.GetBuddyHandleWarning().GetHandleMovedTo() != carol.Public().String() ||
		e.GetBuddyHandleWarning().GetIdentityKey() != bob.Public().String() {
		t.Fatalf("warning %v", e)
	}

	list, err := c.ListBuddies(ctx, &pb.ListBuddiesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, lb := range list.GetBuddies() {
		if lb.GetHandle() == "bob.example.com" {
			found = true
			if lb.GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_MOVED || lb.GetIdentityKey() != bob.Public().String() {
				t.Fatalf("listed %v", lb)
			}
		}
	}
	if !found {
		t.Fatal("bob not listed")
	}
	sn, err := c.GetSafetyNumber(ctx, &pb.GetSafetyNumberRequest{Buddy: "bob"})
	if err != nil || sn.GetBuddy().GetHandleStatus() != pb.HandleStatus_HANDLE_STATUS_MOVED {
		t.Fatalf("safety number buddy %v %v", sn, err)
	}
}

// The daemon refuses bad handle settings at startup.
func TestHandleConfigRefused(t *testing.T) {
	dir, _ := initDir(t)
	conf := cfg(dir)
	conf.Config.DoHResolvers = []string{"https://only.one/dns-query"}
	d, err := Start(context.Background(), conf)
	if err == nil {
		d.Stop()
	}
	if !errors.Is(err, daemon.ErrInvalid) {
		t.Fatalf("started with one resolver: %v", err)
	}
}
