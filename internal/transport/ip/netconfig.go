package ip

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

// Network config limits. They keep a hostile or broken file from making the
// daemon dial thousands of peers.
const (
	MaxNetworkConfigSize = 64 << 10
	MaxNetworkConfigList = 64 // entries per list
)

// defaultNetworkJSON is the built-in bootstrap and relay list (design §6.1:
// "shipped in config, replaceable by the user").
//
//go:embed default_network.json
var defaultNetworkJSON []byte

// NetworkConfig lists the publicly reachable nodes a peer starts from.
type NetworkConfig struct {
	// Bootstrap nodes seed the DHT routing table.
	Bootstrap []peer.AddrInfo
	// Relays are circuit relay v2 nodes to keep a reservation on.
	Relays []peer.AddrInfo
}

// networkConfigJSON is the file format. A nil list means "not set".
type networkConfigJSON struct {
	Comment   string    `json:"comment,omitempty"`
	Bootstrap *[]string `json:"bootstrap,omitempty"`
	Relays    *[]string `json:"relays,omitempty"`
}

// DefaultNetworkConfigJSON is the built-in config file, a template for users.
func DefaultNetworkConfigJSON() []byte { return slices.Clone(defaultNetworkJSON) }

// DefaultNetworkConfig is the built-in config. No community nodes are
// operated yet, so its lists are empty.
func DefaultNetworkConfig() NetworkConfig {
	c, err := parseNetworkConfig(defaultNetworkJSON, NetworkConfig{})
	if err != nil {
		panic("ip: built-in default_network.json: " + err.Error())
	}
	return c
}

// ParseNetworkConfig parses a user config file (JSON) over the built-in
// defaults: each list present in the file, even empty, replaces the default
// one; a list left out keeps it. Unknown fields are errors, to catch typos.
func ParseNetworkConfig(b []byte) (NetworkConfig, error) {
	return parseNetworkConfig(b, DefaultNetworkConfig())
}

// LoadNetworkConfig reads the user config at path. A missing file means the
// built-in defaults.
func LoadNetworkConfig(path string) (NetworkConfig, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return DefaultNetworkConfig(), nil
	}
	if err != nil {
		return NetworkConfig{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxNetworkConfigSize+1))
	if err != nil {
		return NetworkConfig{}, err
	}
	c, err := ParseNetworkConfig(b)
	if err != nil {
		return NetworkConfig{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func parseNetworkConfig(b []byte, base NetworkConfig) (NetworkConfig, error) {
	if len(b) > MaxNetworkConfigSize {
		return NetworkConfig{}, fmt.Errorf("ip: network config is over %d bytes", MaxNetworkConfigSize)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var j networkConfigJSON
	if err := dec.Decode(&j); err != nil {
		return NetworkConfig{}, fmt.Errorf("ip: network config: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return NetworkConfig{}, errors.New("ip: network config: data after the JSON object")
	}
	c := base
	var err error
	if j.Bootstrap != nil {
		if c.Bootstrap, err = parsePeerList("bootstrap", *j.Bootstrap); err != nil {
			return NetworkConfig{}, err
		}
	}
	if j.Relays != nil {
		if c.Relays, err = parsePeerList("relays", *j.Relays); err != nil {
			return NetworkConfig{}, err
		}
	}
	return c, nil
}

// parsePeerList parses multiaddrs ending in /p2p/<ID>, merging addresses of
// the same peer and keeping first-seen order.
func parsePeerList(field string, list []string) ([]peer.AddrInfo, error) {
	if len(list) > MaxNetworkConfigList {
		return nil, fmt.Errorf("ip: network config %s: %d entries, max %d", field, len(list), MaxNetworkConfigList)
	}
	out := []peer.AddrInfo{}
	for i, s := range list {
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			return nil, fmt.Errorf("ip: network config %s[%d]: %w", field, i, err)
		}
		if isCircuit(a) {
			return nil, fmt.Errorf("ip: network config %s[%d]: %s is a relayed address", field, i, s)
		}
		ai, err := peer.AddrInfoFromP2pAddr(a)
		if err != nil {
			return nil, fmt.Errorf("ip: network config %s[%d]: %s: %w (it must end in /p2p/<peer ID>)", field, i, s, err)
		}
		if len(ai.Addrs) == 0 {
			return nil, fmt.Errorf("ip: network config %s[%d]: %s has no address to dial", field, i, s)
		}
		j := slices.IndexFunc(out, func(o peer.AddrInfo) bool { return o.ID == ai.ID })
		if j < 0 {
			out = append(out, peer.AddrInfo{ID: ai.ID})
			j = len(out) - 1
		}
		for _, addr := range ai.Addrs {
			if !slices.ContainsFunc(out[j].Addrs, addr.Equal) {
				out[j].Addrs = append(out[j].Addrs, addr)
			}
		}
	}
	return out, nil
}
