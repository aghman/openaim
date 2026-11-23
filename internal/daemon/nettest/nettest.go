// Package nettest runs the network around daemons under test, on loopback
// only: a node that is both circuit relay and DHT bootstrap, as a
// `openaimd run --public` operator would run, and a connection gater that
// forces every other connection onto a relay circuit.
package nettest

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"

	"github.com/aghman/openaim/internal/transport/ip"
)

// RelayName is the relay's DNS name. Invite links refuse relay circuits on
// private IP addresses, so the relay is named, and Resolver maps the name
// to loopback.
const RelayName = "relay.test"

// Resolver resolves RelayName to 127.0.0.1, and nothing else. Give it to
// every host that dials the relay (daemon.NetworkOptions.Resolver).
func Resolver() network.MultiaddrDNSResolver {
	lo := []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}
	mock := &madns.MockResolver{IP: map[string][]net.IPAddr{RelayName: lo, RelayName + ".": lo}}
	r, err := madns.NewResolver(madns.WithDefaultResolver(mock))
	if err != nil {
		panic(err)
	}
	return swarm.ResolverFromMaDNS{Resolver: r}
}

// Relay is a loopback relay and DHT bootstrap node with a fixed key.
type Relay struct {
	Node  *ip.Node
	DHT   *ip.DHT
	Relay *relay.Relay
	// Addr is its address, /dns4/relay.test/tcp/<port>/p2p/<ID>.
	Addr ma.Multiaddr
}

// StartRelay starts a relay whose circuits are cut after limit (nil: no
// limit). It stops when the test ends.
func StartRelay(t testing.TB, limit *relay.RelayLimit) *Relay {
	t.Helper()
	key, err := ip.LoadOrCreateKey(filepath.Join(t.TempDir(), "relay.key"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := ip.NewNode(ip.NodeOptions{
		Host:     ip.HostOptions{Listen: []string{"/ip4/127.0.0.1/tcp/0"}, PublicReachability: true},
		FixedKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	rl, err := ip.StartRelay(n.Host(), ip.RelayOptions{Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := ip.NewDHT(ctx, n, ip.DHTOptions{Mode: ip.DHTServer})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	var addr ma.Multiaddr
	for _, a := range n.Host().Addrs() {
		if port, err := a.ValueForProtocol(ma.P_TCP); err == nil {
			addr = ma.StringCast("/dns4/" + RelayName + "/tcp/" + port + "/p2p/" + n.ID().String())
			break
		}
	}
	if addr == nil {
		t.Fatal("relay has no TCP address")
	}
	return &Relay{Node: n, DHT: d, Relay: rl, Addr: addr}
}

// ID is the relay's peer ID.
func (r *Relay) ID() peer.ID { return r.Node.ID() }

// Config is a network config with the relay as the only bootstrap node and
// relay.
func (r *Relay) Config() ip.NetworkConfig {
	ai := peer.AddrInfo{ID: r.ID(), Addrs: []ma.Multiaddr{r.Addr.Decapsulate(ma.StringCast("/p2p/" + r.ID().String()))}}
	return ip.NetworkConfig{Bootstrap: []peer.AddrInfo{ai}, Relays: []peer.AddrInfo{ai}}
}

// WriteNetworkJSON writes network.json into a daemon's data dir, naming
// the relay as bootstrap node and relay.
func (r *Relay) WriteNetworkJSON(t testing.TB, dataDir string) {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"comment":   "test network",
		"bootstrap": []string{r.Addr.String()},
		"relays":    []string{r.Addr.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "network.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// RelayOnly is a connection gater that allows direct connections only with
// the Allow peer (the relay); everything else must use a relay circuit, as
// between two peers behind NATs that can't hole-punch.
type RelayOnly struct{ Allow peer.ID }

var _ connmgr.ConnectionGater = RelayOnly{}

func (RelayOnly) InterceptPeerDial(peer.ID) bool { return true }

func (g RelayOnly) InterceptAddrDial(p peer.ID, a ma.Multiaddr) bool {
	return p == g.Allow || isCircuit(a)
}

func (RelayOnly) InterceptAccept(network.ConnMultiaddrs) bool { return true }

func (g RelayOnly) InterceptSecured(_ network.Direction, p peer.ID, c network.ConnMultiaddrs) bool {
	return p == g.Allow || isCircuit(c.RemoteMultiaddr())
}

func (RelayOnly) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) { return true, 0 }

func isCircuit(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}
