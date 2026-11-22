package handle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// HTTPS proof limits (spec/handle.md §5).
const (
	ProofPath           = "/.well-known/openaim"
	MaxProofSize        = 4 << 10
	DefaultProofTimeout = 10 * time.Second
)

// Proof errors.
var (
	ErrRedirect      = errors.New("handle: HTTPS proof redirected")
	ErrForbiddenAddr = errors.New("handle: address not allowed")
)

// ProofConfig controls HTTPS proof fetches. The zero value is the production
// setting; the fields exist so tests can point fetches at httptest servers.
type ProofConfig struct {
	// LookupIP finds the handle's addresses. Nil uses the Verifier's DoH
	// resolvers, never the system resolver.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
	// AllowAddr decides which addresses may be dialed. Nil is PublicAddr.
	AllowAddr func(netip.Addr) bool
	// Port to connect to. Zero is 443. The URL never carries a port.
	Port uint16
	// RootCAs verifies the server. Nil is the system's WebPKI roots.
	RootCAs *x509.CertPool
	// MaxSize caps the body. Zero is MaxProofSize.
	MaxSize int64
	// Timeout bounds the whole fetch. Zero is DefaultProofTimeout.
	Timeout time.Duration
}

// FetchProof fetches and parses https://<h>/.well-known/openaim. The record
// is not verified; Verify does that.
//
// The fetch follows no redirects, uses no proxy, needs a certificate valid
// for h, and refuses to connect to any address AllowAddr rejects. The check
// runs in the dialer on the address actually being connected to, so a DNS
// answer that changes between lookups (rebinding) can't slip past it. If any
// of the handle's addresses is forbidden, the fetch is refused outright.
func (v *Verifier) FetchProof(ctx context.Context, h string) (*Record, error) {
	if err := Validate(h); err != nil {
		return nil, err
	}
	p := v.Proof
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = DefaultProofTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lookup := p.LookupIP
	if lookup == nil {
		lookup = v.lookupIP
	}
	allow := p.AllowAddr
	if allow == nil {
		allow = PublicAddr
	}
	port := p.Port
	if port == 0 {
		port = 443
	}
	maxSize := p.MaxSize
	if maxSize <= 0 {
		maxSize = MaxProofSize
	}

	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !allow(ap.Addr()) {
				return fmt.Errorf("%w: %s", ErrForbiddenAddr, address)
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy: nil, // a proxy would dial for us, around the guard
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil || host != h {
				return nil, fmt.Errorf("%w: unexpected dial to %s", ErrForbiddenAddr, addr)
			}
			addrs, err := lookup(ctx, h)
			if err != nil {
				return nil, err
			}
			if len(addrs) == 0 {
				return nil, fmt.Errorf("%w: no addresses for %s", ErrNotFound, h)
			}
			for _, a := range addrs {
				if !allow(a) {
					return nil, fmt.Errorf("%w: %s resolves to %s", ErrForbiddenAddr, h, a)
				}
			}
			var lastErr error
			for _, a := range addrs[:min(len(addrs), maxAddrs)] {
				c, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(a, port).String())
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSClientConfig:        &tls.Config{RootCAs: p.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: noRedirects}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+h+ProofPath, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ErrForbiddenAddr) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnreachable) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("%w: status %d to %q", ErrRedirect, resp.StatusCode, resp.Header.Get("Location"))
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, fmt.Errorf("%w: HTTPS proof status %d", ErrNotFound, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%w: HTTPS proof status %d", ErrUnreachable, resp.StatusCode)
	case resp.ContentLength > maxSize:
		return nil, fmt.Errorf("%w: Content-Length %d", ErrTooLarge, resp.ContentLength)
	}
	body, err := readCapped(resp.Body, maxSize)
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	// Files usually end in a newline; nothing else around the record is
	// allowed.
	return ParseRecord(strings.Trim(string(body), " \t\r\n"))
}

// nonPublic lists special-purpose ranges that netip's predicates don't
// already cover (IANA IPv4 and IPv6 special-purpose registries).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and broadcast
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("100::/64"),        // discard-only
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments, incl. Teredo
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("3fff::/20"),       // documentation
	netip.MustParsePrefix("fec0::/10"),       // site-local (deprecated)
}

var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// PublicAddr reports whether a is a globally routable unicast address: not
// unspecified, loopback, private, link-local, multicast or otherwise special.
// IPv6 forms that embed an IPv4 address (mapped, NAT64, 6to4) are judged by
// the embedded address. It is the default SSRF guard for HTTPS proofs.
func PublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	if a.Is6() {
		b := a.As16()
		switch {
		case nat64.Contains(a):
			return PublicAddr(netip.AddrFrom4([4]byte(b[12:16])))
		case sixToFour.Contains(a):
			return PublicAddr(netip.AddrFrom4([4]byte(b[2:6])))
		}
	}
	return true
}
