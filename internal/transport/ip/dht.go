package ip

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// The private OpenAIM DHT (design §6.1). Its own protocol keeps it apart from
// the IPFS Amino DHT.
const (
	DHTProtocolPrefix protocol.ID = "/openaim"
	DHTProtocol       protocol.ID = DHTProtocolPrefix + "/kad/1.0.0"
	// DefaultDHTBootstrapTimeout bounds how long a new host waits for its
	// DHT to find peers before it becomes current.
	DefaultDHTBootstrapTimeout = 10 * time.Second
)

// DHTMode selects whether a node answers DHT queries.
type DHTMode int

const (
	// DHTAuto serves queries only once AutoNAT finds the host publicly
	// reachable. Right for ordinary peers.
	DHTAuto DHTMode = iota
	// DHTClient never serves queries.
	DHTClient
	// DHTServer always serves queries. Right for bootstrap and other public
	// nodes (and for loopback tests).
	DHTServer
)

func (m DHTMode) opt() (dht.ModeOpt, error) {
	switch m {
	case DHTAuto:
		return dht.ModeAuto, nil
	case DHTClient:
		return dht.ModeClient, nil
	case DHTServer:
		return dht.ModeServer, nil
	}
	return 0, fmt.Errorf("ip: unknown DHT mode %d", m)
}

// DHTOptions configures NewDHT.
type DHTOptions struct {
	Mode DHTMode
	// Bootstrap peers, usually NetworkConfig.Bootstrap. A node that is
	// itself listed is skipped.
	Bootstrap []peer.AddrInfo
	// BootstrapTimeout: 0 means DefaultDHTBootstrapTimeout. Running out is
	// not an error (the first node of a network has nobody to find); the DHT
	// goes on trying in the background.
	BootstrapTimeout time.Duration
}

// DHT runs the private Kademlia DHT on a Node and follows its rotations:
// every host generation gets its own DHT instance, with an empty routing
// table and datastore, bootstrapped from the configured bootstrap peers only
// before the host becomes current, and closed when the host retires. Nothing
// carries over between generations: seeding the new routing table from the
// old one, or serving records the old peer ID was given, would link them.
// Records stored on a retired instance are lost; publishers republish.
type DHT struct {
	node   *Node
	opts   DHTOptions
	mode   dht.ModeOpt
	detach func()

	mu   sync.RWMutex
	inst map[peer.ID]*dht.IpfsDHT // by host ID, for live hosts
}

// NewDHT starts the DHT on n's current host and every later one.
func NewDHT(ctx context.Context, n *Node, o DHTOptions) (*DHT, error) {
	mode, err := o.Mode.opt()
	if err != nil {
		return nil, err
	}
	if o.BootstrapTimeout <= 0 {
		o.BootstrapTimeout = DefaultDHTBootstrapTimeout
	}
	d := &DHT{node: n, opts: o, mode: mode, inst: map[peer.ID]*dht.IpfsDHT{}}
	if d.detach, err = n.Attach(ctx, d.start); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DHT) start(ctx context.Context, h host.Host) (func(), error) {
	var boot []peer.AddrInfo
	for _, b := range d.opts.Bootstrap {
		if b.ID != h.ID() {
			boot = append(boot, b)
		}
	}
	kd, err := dht.New(h,
		dht.ProtocolPrefix(DHTProtocolPrefix),
		dht.Mode(d.mode),
		dht.Validator(DHTValidator()),
		// Rendezvous needs only values. Provider records would be one more
		// thing for strangers to store on us.
		dht.DisableProviders(),
		// Never save the routing table: it would link generations.
		dht.RoutingTablePersistence(0),
		dht.BootstrapPeers(boot...),
		// Lookups can return our own draining host (other nodes still list
		// it). Records stored there die with it, so keep our generations
		// out of each other's routing tables and queries.
		dht.RoutingTableFilter(func(_ any, p peer.ID) bool { return !d.node.owns(p) }),
		dht.QueryFilter(func(_ any, ai peer.AddrInfo) bool { return !d.node.owns(ai.ID) }),
	)
	if err != nil {
		return nil, fmt.Errorf("ip: DHT: %w", err)
	}
	bootstrapDHT(ctx, h, kd, boot, d.opts.BootstrapTimeout)
	d.mu.Lock()
	d.inst[h.ID()] = kd
	d.mu.Unlock()
	return func() {
		d.mu.Lock()
		delete(d.inst, h.ID())
		d.mu.Unlock()
		kd.Close()
	}, nil
}

// bootstrapDHT connects to the bootstrap peers and runs one routing table
// refresh, giving up quietly after timeout.
func bootstrapDHT(ctx context.Context, h host.Host, kd *dht.IpfsDHT, boot []peer.AddrInfo, timeout time.Duration) {
	if len(boot) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, b := range boot {
		wg.Go(func() { h.Connect(ctx, b) })
	}
	wg.Wait()
	// Peers enter the routing table once identify shows they speak the DHT
	// protocol.
	for kd.RoutingTable().Size() == 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case <-kd.RefreshRoutingTable():
	case <-ctx.Done():
	}
}

// Instance is the DHT instance on the node's current host.
func (d *DHT) Instance() (*dht.IpfsDHT, error) {
	id := d.node.ID()
	d.mu.RLock()
	defer d.mu.RUnlock()
	kd := d.inst[id]
	if kd == nil {
		return nil, errors.New("ip: DHT closed")
	}
	return kd, nil
}

// PutValue stores a raw record from the current host. The value must pass
// DHTValidator.
func (d *DHT) PutValue(ctx context.Context, key string, value []byte) error {
	kd, err := d.Instance()
	if err != nil {
		return err
	}
	return kd.PutValue(ctx, key, value)
}

// GetValue finds the best record for key from the current host.
func (d *DHT) GetValue(ctx context.Context, key string) ([]byte, error) {
	kd, err := d.Instance()
	if err != nil {
		return nil, err
	}
	return kd.GetValue(ctx, key)
}

// PutRendezvous signs payload with priv and stores it under
// RendezvousKey(priv.Public()). It returns the key.
func (d *DHT) PutRendezvous(ctx context.Context, priv ed25519.PrivateKey, seq uint64, payload []byte) (string, error) {
	v, err := SignRendezvousRecord(priv, seq, payload)
	if err != nil {
		return "", err
	}
	key := RendezvousKey(priv.Public().(ed25519.PublicKey))
	return key, d.PutValue(ctx, key, v)
}

// GetRendezvous finds and verifies the newest rendezvous record under key.
func (d *DHT) GetRendezvous(ctx context.Context, key string) (RendezvousRecord, error) {
	v, err := d.GetValue(ctx, key)
	if err != nil {
		return RendezvousRecord{}, err
	}
	return ParseRendezvousRecord(key, v)
}

// Close stops the DHT on every host of the node.
func (d *DHT) Close() error {
	d.detach()
	return nil
}
