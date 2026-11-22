package rendezvous

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	dhtpb "github.com/libp2p/go-libp2p-kad-dht/pb"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/aghman/openaim/internal/frame"
	"github.com/aghman/openaim/internal/transport/ip"
)

// dhtNode is an ip.Node running the DHT on loopback.
type dhtNode struct {
	*ip.Node
	dht *ip.DHT
}

func newDHTNode(t *testing.T, boot []peer.AddrInfo) *dhtNode {
	t.Helper()
	n, err := ip.NewNode(ip.NodeOptions{
		Host:     ip.HostOptions{Listen: []string{"/ip4/127.0.0.1/tcp/0"}},
		Interval: -1, // rotate only when told
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	d, err := ip.NewDHT(ctx, n, ip.DHTOptions{Mode: ip.DHTServer, Bootstrap: boot, BootstrapTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return &dhtNode{n, d}
}

func (n *dhtNode) rtSize(t *testing.T) int {
	kd, err := n.dht.Instance()
	if err != nil {
		t.Fatal(err)
	}
	return kd.RoutingTable().Size()
}

// lookup retries until want(f) holds, since a fresh put may still be on its
// way to some storers.
func lookup(t *testing.T, n *dhtNode, kdir [32]byte, want func(Found) bool) Found {
	t.Helper()
	var f Found
	var err error
	waitFor(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f, err = Lookup(ctx, n.dht, kdir, time.Now())
		return err == nil && want(f)
	})
	return f
}

// TestDHTRendezvous is the ticket's acceptance test: on a loopback DHT, A
// publishes for B, B finds A's current peer ID and dials it, B finds the new
// one after A rotates, nobody else can read the record, and what the DHT
// nodes store contains none of A's peer IDs or addresses.
func TestDHTRendezvous(t *testing.T) {
	s1 := newDHTNode(t, nil)
	boot := []peer.AddrInfo{{ID: s1.ID(), Addrs: s1.Host().Addrs()}}
	s2, s3 := newDHTNode(t, boot), newDHTNode(t, boot)
	a, b := newDHTNode(t, boot), newDHTNode(t, boot)
	all := []*dhtNode{s1, s2, s3, a, b}
	waitFor(t, func() bool {
		for _, n := range all {
			if n.rtSize(t) < 3 {
				return false
			}
		}
		return true
	})

	ab, ba := newPair(t, 0xA1, 0xB0)
	ca, _ := newPair(t, 0xC2, 0xA1) // a third identity's pair with A
	var ev events
	p := newTestPublisher(t, PublisherOptions{Store: a.dht, Node: a.Node, PutInterval: -1, OnPublish: ev.add})
	p.SetPair(ab)
	es := ev.wait(t, 0, 1)
	if es[0].Err != nil || es[0].ID != a.ID() {
		t.Fatalf("publish: %+v", es[0])
	}
	key := es[0].Key

	// B finds A and can dial the result.
	id1 := a.ID()
	f := lookup(t, b, ba.Recv, func(f Found) bool { return f.ID == id1 })
	if len(f.Addrs) == 0 || f.Day != frame.Day(time.Now()) {
		t.Errorf("found %+v", f)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A fresh host, which knows A only from the record, dials it.
	h, err := ip.NewHost(ip.HostOptions{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Connect(ctx, f.AddrInfo()); err != nil {
		t.Fatalf("dialing the found address: %v", err)
	}

	// A rotates; the publisher republishes from the new host, and B finds
	// the new peer ID.
	if err := a.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	id2 := a.ID()
	waitFor(t, func() bool {
		ev.mu.Lock()
		defer ev.mu.Unlock()
		return slices.ContainsFunc(ev.es, func(e PublishEvent) bool { return e.ID == id2 && e.Err == nil })
	})
	lookup(t, b, ba.Recv, func(f Found) bool { return f.ID == id2 })

	// Nobody outside the pair can find or read it: not a third user with a
	// pair of their own with A, nor A's key in the other direction.
	if _, err := Lookup(ctx, s2.dht, ca.Recv, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("outsider lookup: %v", err)
	}
	r, err := s2.dht.GetRendezvous(ctx, key) // a storer that knows the key
	if err != nil {
		t.Fatal(err)
	}
	day := frame.Day(time.Now())
	for name, k := range map[string]Keys{"outsider": Derive(ca.Recv, day), "reverse direction": Derive(ab.Recv, day)} {
		if _, err := Open(k, r); !errors.Is(err, ErrBadLocator) {
			t.Errorf("%s opened the record: %v", name, err)
		}
		// Even with the record's own public key swapped in, the AEAD fails.
		k.Pub = r.PublicKey
		if _, err := Open(k, r); !errors.Is(err, ErrBadLocator) {
			t.Errorf("%s opened the record with its public key: %v", name, err)
		}
	}

	// What the storers hold: ask every node directly for its local record.
	var secrets [][]byte
	for _, id := range []peer.ID{id1, id2} {
		secrets = append(secrets, []byte(id), []byte(id.String()))
	}
	for _, addr := range a.Addrs() {
		secrets = append(secrets, addr.Bytes(), []byte(addr.String()))
	}
	stored := 0
	for _, asker := range []*dhtNode{s1, s2} {
		kd, err := asker.dht.Instance()
		if err != nil {
			t.Fatal(err)
		}
		pm, err := dhtpb.NewProtocolMessenger(kd.MessageSender())
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range all {
			if n == asker {
				continue
			}
			rec, _, err := pm.GetValue(ctx, n.ID(), key)
			if err != nil || rec == nil {
				continue
			}
			stored++
			for _, field := range [][]byte{rec.GetKey(), rec.GetValue()} {
				for _, s := range secrets {
					if bytes.Contains(field, s) {
						t.Errorf("%s stores %x in the clear", n.ID(), s)
					}
				}
			}
			if len(rec.GetValue()) != 41+NonceSize+PadBlock+16+64 {
				t.Errorf("stored value is %d bytes, not one padded block", len(rec.GetValue()))
			}
		}
	}
	if stored == 0 {
		t.Fatal("no node stores the record")
	}
}
