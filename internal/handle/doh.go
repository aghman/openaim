package handle

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DefaultResolvers are two independent DNS-over-HTTPS resolvers, Cloudflare
// and Quad9. They are IP literals (both certificates name the IP), so finding
// the resolvers needs no DNS lookup of its own.
var DefaultResolvers = []string{
	"https://1.1.1.1/dns-query",
	"https://9.9.9.9/dns-query",
}

// DoH limits (spec/handle.md §4).
const (
	MaxDoHResponse    = 16 << 10
	DefaultDoHTimeout = 5 * time.Second
	maxCNAMEChain     = 8
	maxAddrs          = 8
	dnsMessageType    = "application/dns-message"
)

// Lookup errors. ErrUnreachable marks failures that say nothing about the
// handle itself (network, timeouts, resolver errors), so callers can retry
// rather than warn.
var (
	ErrNotFound    = errors.New("handle: no record")
	ErrUnreachable = errors.New("handle: lookup failed")
	ErrDisagree    = errors.New("handle: resolvers disagree")
	ErrAmbiguous   = errors.New("handle: more than one record")
	ErrTooLarge    = errors.New("handle: response too large")
	ErrConfig      = errors.New("handle: bad configuration")
)

var defaultDoHClient = sync.OnceValue(func() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// No proxy: lookups go straight to the configured resolvers.
			Proxy:                  nil,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:      true,
			TLSHandshakeTimeout:    DefaultDoHTimeout,
			ResponseHeaderTimeout:  DefaultDoHTimeout,
			MaxResponseHeaderBytes: 16 << 10,
			IdleConnTimeout:        90 * time.Second,
		},
		CheckRedirect: noRedirects,
	}
})

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func (v *Verifier) resolvers() ([]string, error) {
	rs := v.Resolvers
	if rs == nil {
		rs = DefaultResolvers
	}
	if len(rs) < 2 {
		return nil, fmt.Errorf("%w: need at least two resolvers, have %d", ErrConfig, len(rs))
	}
	for i, r := range rs {
		if !strings.HasPrefix(r, "https://") {
			return nil, fmt.Errorf("%w: resolver %q is not an https URL", ErrConfig, r)
		}
		if slices.Contains(rs[:i], r) {
			return nil, fmt.Errorf("%w: resolver %q listed twice", ErrConfig, r)
		}
	}
	return rs, nil
}

// lookupTXT asks every resolver for the handle's TXT record. All of them
// must give the same answer: the same set of v1 records, or all "none".
// Any failure fails the lookup, because a resolver that can be made to fail
// must not be able to make the others' answer count alone.
func (v *Verifier) lookupTXT(ctx context.Context, h string) (string, error) {
	rs, err := v.resolvers()
	if err != nil {
		return "", err
	}
	name := recordPrefix + h + "."
	q, err := buildQuery(name, dnsmessage.TypeTXT)
	if err != nil {
		return "", err
	}
	type outcome struct {
		texts []string
		err   error
	}
	outs := make([]outcome, len(rs))
	var wg sync.WaitGroup
	for i, r := range rs {
		wg.Go(func() {
			msg, err := v.exchange(ctx, r, q)
			if err == nil {
				outs[i].texts, err = txtCandidates(msg, name)
			}
			outs[i].err = err
		})
	}
	wg.Wait()

	for i, o := range outs {
		if o.err != nil && !errors.Is(o.err, ErrNotFound) {
			return "", fmt.Errorf("resolver %s: %w", rs[i], o.err)
		}
	}
	for i := 1; i < len(outs); i++ {
		if (outs[i].err == nil) != (outs[0].err == nil) || !slices.Equal(outs[i].texts, outs[0].texts) {
			return "", fmt.Errorf("%w: %s and %s gave different answers for %s", ErrDisagree, rs[0], rs[i], name)
		}
	}
	switch {
	case outs[0].err != nil:
		return "", fmt.Errorf("%w: no TXT record at %s", ErrNotFound, name)
	case len(outs[0].texts) > 1:
		return "", fmt.Errorf("%w: %d v1 records at %s", ErrAmbiguous, len(outs[0].texts), name)
	}
	return outs[0].texts[0], nil
}

// lookupIP finds a host's addresses for an HTTPS proof fetch. TLS
// authenticates the server, so one resolver's answer is enough; the others
// are tried only if it fails.
func (v *Verifier) lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	rs, err := v.resolvers()
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		var addrs []netip.Addr
		var hardErr error
		for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
			a, err := v.lookupAddrs(ctx, r, host+".", t)
			if err != nil && !errors.Is(err, ErrNotFound) {
				hardErr = err
			}
			addrs = append(addrs, a...)
		}
		switch {
		case len(addrs) > 0:
			if len(addrs) > maxAddrs {
				addrs = addrs[:maxAddrs]
			}
			return addrs, nil
		case hardErr == nil:
			return nil, fmt.Errorf("%w: no addresses for %s", ErrNotFound, host)
		}
		err = fmt.Errorf("resolver %s: %w", r, hardErr)
	}
	return nil, err
}

func (v *Verifier) lookupAddrs(ctx context.Context, resolver, name string, t dnsmessage.Type) ([]netip.Addr, error) {
	q, err := buildQuery(name, t)
	if err != nil {
		return nil, err
	}
	msg, err := v.exchange(ctx, resolver, q)
	if err != nil {
		return nil, err
	}
	bodies, err := parseAnswer(msg, name, t)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, b := range bodies {
		switch r := b.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(r.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(r.AAAA))
		}
	}
	return out, nil
}

// exchange sends one RFC 8484 POST query and returns the response message.
func (v *Verifier) exchange(ctx context.Context, resolver string, q []byte) ([]byte, error) {
	timeout := v.DoHTimeout
	if timeout <= 0 {
		timeout = DefaultDoHTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resolver, bytes.NewReader(q))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfig, err)
	}
	req.Header.Set("Content-Type", dnsMessageType)
	req.Header.Set("Accept", dnsMessageType)
	client := v.Client
	if client == nil {
		client = defaultDoHClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP status %d", ErrUnreachable, resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != dnsMessageType {
		return nil, fmt.Errorf("%w: content type %q", ErrUnreachable, resp.Header.Get("Content-Type"))
	}
	body, err := readCapped(resp.Body, MaxDoHResponse)
	if err != nil {
		// A resolver sending junk is the resolver's fault, not the handle's.
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return body, nil
}

// readCapped reads all of r, failing with ErrTooLarge past max bytes.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, max)
	}
	return b, nil
}

// buildQuery packs a recursive query for name (with its trailing dot). The
// ID is 0, as RFC 8484 §4.1 recommends: HTTPS already pairs the response
// with the request.
func buildQuery(name string, t dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSyntax, err)
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: t, Class: dnsmessage.ClassINET}},
	}
	return m.Pack()
}

// txtCandidates returns the v1 handle records among the TXT answers for
// name, each record's strings joined, sorted and without duplicates. Other
// TXT records at the name are ignored.
func txtCandidates(msg []byte, name string) ([]string, error) {
	bodies, err := parseAnswer(msg, name, dnsmessage.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, b := range bodies {
		txt, ok := b.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		if s := strings.Join(txt.TXT, ""); isCandidate(s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no v1 record among the TXT answers", ErrNotFound)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

var errBadResponse = errors.New("bad DNS response")

func badResponse(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrUnreachable, errBadResponse, fmt.Sprintf(format, args...))
}

// parseAnswer checks that msg answers the query for (name, t, IN) and
// returns the records of type t at name, following a CNAME chain in the
// answer section if there is one. NXDOMAIN and an empty answer give
// ErrNotFound; anything malformed gives ErrUnreachable.
func parseAnswer(msg []byte, name string, t dnsmessage.Type) ([]dnsmessage.ResourceBody, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, badResponse("%v", err)
	}
	switch {
	case !h.Response:
		return nil, badResponse("not a response")
	case h.ID != 0:
		return nil, badResponse("ID %d, sent 0", h.ID)
	case h.OpCode != 0:
		return nil, badResponse("opcode %d", h.OpCode)
	case h.Truncated:
		return nil, badResponse("truncated")
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil, badResponse("%v", err)
	}
	if len(qs) != 1 || !sameName(qs[0].Name.String(), name) || qs[0].Type != t || qs[0].Class != dnsmessage.ClassINET {
		return nil, badResponse("answers a different question")
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, fmt.Errorf("%w: NXDOMAIN for %s", ErrNotFound, name)
	default:
		return nil, fmt.Errorf("%w: resolver returned %v", ErrUnreachable, h.RCode)
	}

	cnames := map[string]string{}
	found := map[string][]dnsmessage.ResourceBody{}
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, badResponse("%v", err)
		}
		owner := strings.ToLower(ah.Name.String())
		var body dnsmessage.ResourceBody
		switch {
		case ah.Class != dnsmessage.ClassINET:
			err = p.SkipAnswer()
		case ah.Type == dnsmessage.TypeCNAME:
			var c dnsmessage.CNAMEResource
			if c, err = p.CNAMEResource(); err == nil {
				cnames[owner] = strings.ToLower(c.CNAME.String())
			}
		case ah.Type == t && t == dnsmessage.TypeTXT:
			var r dnsmessage.TXTResource
			r, err = p.TXTResource()
			body = &r
		case ah.Type == t && t == dnsmessage.TypeA:
			var r dnsmessage.AResource
			r, err = p.AResource()
			body = &r
		case ah.Type == t && t == dnsmessage.TypeAAAA:
			var r dnsmessage.AAAAResource
			r, err = p.AAAAResource()
			body = &r
		default:
			err = p.SkipAnswer()
		}
		if err != nil {
			return nil, badResponse("%v", err)
		}
		if body != nil {
			found[owner] = append(found[owner], body)
		}
	}

	at := strings.ToLower(name)
	for range maxCNAMEChain + 1 {
		if rs := found[at]; len(rs) > 0 {
			return rs, nil
		}
		next, ok := cnames[at]
		if !ok {
			break
		}
		at = next
	}
	return nil, fmt.Errorf("%w: no %v answer for %s", ErrNotFound, t, name)
}

// sameName compares DNS names case-insensitively, as DNS does for ASCII.
func sameName(a, b string) bool { return strings.EqualFold(a, b) }
