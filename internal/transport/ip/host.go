package ip

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	ma "github.com/multiformats/go-multiaddr"
)

// UserAgent is what OpenAIM hosts announce over identify.
const UserAgent = "openaim/0 (m0 spike)"

// HostOptions configures NewHost.
type HostOptions struct {
	// Key is the host's network key. Nil means a fresh Ed25519 key, which is
	// what the design wants for ordinary peers (§6.1: rotated on restart).
	Key crypto.PrivKey
	// Listen are multiaddr strings; empty means DefaultListen(0).
	Listen []string
	// HolePunching enables DCUtR. Tracer, if set, receives its events.
	HolePunching bool
	Tracer       holepunch.EventTracer
	// PublicReachability tells the host it is publicly reachable, skipping
	// AutoNAT. Set it on relays and bootstrap nodes.
	PublicReachability bool
	// NATPortMap tries UPnP / NAT-PMP port mapping on the home router.
	NATPortMap bool
	// Gater, if set, can veto connections (tests and the spike use it to
	// force traffic onto a relay).
	Gater connmgr.ConnectionGater
}

// DefaultListen returns TCP and QUIC listen addresses on all IPv4 and IPv6
// interfaces. Port 0 picks a random port.
func DefaultListen(port int) []string {
	return []string{
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
		fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port),
		fmt.Sprintf("/ip6/::/tcp/%d", port),
		fmt.Sprintf("/ip6/::/udp/%d/quic-v1", port),
	}
}

// NewHost builds a libp2p host. The relay client (dialing and accepting
// circuit connections) is always on.
func NewHost(o HostOptions) (host.Host, error) {
	key := o.Key
	if key == nil {
		var err error
		if key, _, err = crypto.GenerateEd25519Key(nil); err != nil {
			return nil, err
		}
	}
	listen := o.Listen
	if len(listen) == 0 {
		listen = DefaultListen(0)
	}
	opts := []libp2p.Option{
		libp2p.Identity(key),
		libp2p.ListenAddrStrings(listen...),
		libp2p.UserAgent(UserAgent),
		libp2p.EnableRelay(),
	}
	if o.HolePunching {
		var hp []holepunch.Option
		if o.Tracer != nil {
			hp = append(hp, holepunch.WithTracer(o.Tracer))
		}
		opts = append(opts, libp2p.EnableHolePunching(hp...))
	}
	if o.PublicReachability {
		opts = append(opts, libp2p.ForceReachabilityPublic())
	}
	if o.NATPortMap {
		opts = append(opts, libp2p.NATPortMap())
	}
	if o.Gater != nil {
		opts = append(opts, libp2p.ConnectionGater(o.Gater))
	}
	return libp2p.New(opts...)
}

// LoadOrCreateKey reads a libp2p private key from path, creating a new
// Ed25519 key there (mode 0600) if the file doesn't exist. Relays use it so
// their address stays stable across restarts.
func LoadOrCreateKey(path string) (crypto.PrivKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return crypto.UnmarshalPrivateKey(b)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, _, err := crypto.GenerateEd25519Key(nil)
	if err != nil {
		return nil, err
	}
	b, err = crypto.MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// CircuitAddr is the address at which target can be reached through the
// relay at relayAddr. relayAddr must end in /p2p/<relay ID>.
func CircuitAddr(relayAddr ma.Multiaddr, target peer.ID) (ma.Multiaddr, error) {
	if _, err := relayAddr.ValueForProtocol(ma.P_P2P); err != nil {
		return nil, fmt.Errorf("relay address %s has no /p2p/ component", relayAddr)
	}
	return ma.NewMultiaddr(relayAddr.String() + "/p2p-circuit/p2p/" + target.String())
}

// IsRelayed reports whether c runs through a circuit relay.
func IsRelayed(c network.Conn) bool { return isCircuit(c.RemoteMultiaddr()) }

// PathOf describes how c reaches the peer, for logs: "direct/tcp",
// "direct/quic-v1", "relay" or "relay (limited)".
func PathOf(c network.Conn) string {
	if IsRelayed(c) {
		if c.Stat().Limited {
			return "relay (limited)"
		}
		return "relay"
	}
	for _, p := range []string{"quic-v1", "webtransport", "tcp"} {
		if strings.Contains(c.RemoteMultiaddr().String(), "/"+p) {
			return "direct/" + p
		}
	}
	return "direct"
}

// RelayOnlyGater refuses every direct (non-circuit) connection to or from
// Peer, so all traffic with it goes through a relay. Hole punching becomes
// impossible too, since its result is a direct connection.
type RelayOnlyGater struct {
	Peer peer.ID
}

var _ connmgr.ConnectionGater = RelayOnlyGater{}

func (RelayOnlyGater) InterceptPeerDial(peer.ID) bool { return true }

func (g RelayOnlyGater) InterceptAddrDial(p peer.ID, a ma.Multiaddr) bool {
	return p != g.Peer || isCircuit(a)
}

func (RelayOnlyGater) InterceptAccept(network.ConnMultiaddrs) bool { return true }

func (g RelayOnlyGater) InterceptSecured(_ network.Direction, p peer.ID, c network.ConnMultiaddrs) bool {
	return p != g.Peer || isCircuit(c.RemoteMultiaddr())
}

func (RelayOnlyGater) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) {
	return true, 0
}

func isCircuit(a ma.Multiaddr) bool {
	_, err := a.ValueForProtocol(ma.P_CIRCUIT)
	return err == nil
}
