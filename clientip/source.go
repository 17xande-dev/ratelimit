// Package clientip resolves an HTTP client's IP using an explicit proxy trust policy.
package clientip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

const (
	forwardedFor     = "X-Forwarded-For"
	maxForwardedHops = 64
	maxAddressBytes  = 256
)

// Config selects a proxy policy. Set at most one field.
type Config struct {
	// TrustedProxies identifies controlled hops that append their actual peers
	// to X-Forwarded-For. IPv4 and IPv6 /0 prefixes are not permitted.
	TrustedProxies []netip.Prefix
	// TrustedHeader requires an ingress that controls the named header and
	// cannot be bypassed. X-Forwarded-For uses its rightmost entry; any other
	// header must contain exactly one address on one line.
	TrustedHeader string
}

// Source is a client address policy. Its zero value uses only the peer address.
// A Source can be shared by concurrent handlers.
type Source struct {
	proxies           []netip.Prefix
	header            string
	replacedForwarded bool
}

// New validates and copies the configuration.
func New(cfg Config) (Source, error) {
	header := strings.TrimSpace(cfg.TrustedHeader)
	if len(cfg.TrustedProxies) != 0 && header != "" {
		return Source{}, fmt.Errorf("clientip: trusted proxies and a trusted header are mutually exclusive")
	}
	if cfg.TrustedHeader != "" && !validHeaderName(header) {
		return Source{}, fmt.Errorf("clientip: invalid trusted header name")
	}
	src := Source{header: http.CanonicalHeaderKey(header)}
	for _, p := range cfg.TrustedProxies {
		if !p.IsValid() {
			return Source{}, fmt.Errorf("clientip: invalid trusted proxy prefix")
		}
		if p.Bits() == 0 || (p.Addr().Is4In6() && p.Bits() == 96) {
			return Source{}, fmt.Errorf("clientip: trusted proxy prefix %s would trust every address in its family (/0)", p)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return Source{}, fmt.Errorf("clientip: mapped proxy prefix must be at least /96")
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		src.proxies = append(src.proxies, p.Masked())
	}
	return src, nil
}

// ParseSource maps a deployment's named setting to a policy. "remote" ignores
// headers, "cloudflare" reads only CF-Connecting-IP, and "forwarded" takes the
// first entry of the first X-Forwarded-For line. Use "forwarded" only when the
// sole ingress replaces every incoming copy of that header; an appending proxy
// instead needs TrustedProxies or an explicit TrustedHeader.
func ParseSource(value string) (Source, error) {
	switch strings.TrimSpace(value) {
	case "remote":
		return Source{}, nil
	case "cloudflare":
		return New(Config{TrustedHeader: "CF-Connecting-IP"})
	case "forwarded":
		return Source{header: forwardedFor, replacedForwarded: true}, nil
	default:
		return Source{}, fmt.Errorf("clientip: expected remote, forwarded or cloudflare; got %q", value)
	}
}

// Addr returns the trusted header address, falling back to the peer. An
// unparseable peer with no usable trusted header yields an invalid netip.Addr.
func (s Source) Addr(r *http.Request) netip.Addr {
	if addr := s.HeaderAddr(r); addr.IsValid() {
		return addr
	}
	return parseAddr(r.RemoteAddr)
}

// HeaderAddr returns a header address only if it is usable under this policy.
// It returns an invalid address rather than falling back to the peer.
func (s Source) HeaderAddr(r *http.Request) netip.Addr {
	if s.header != "" {
		lines := r.Header.Values(s.header)
		if len(lines) == 0 {
			return netip.Addr{}
		}
		switch {
		case s.replacedForwarded:
			first, _, _ := strings.Cut(lines[0], ",")
			return parseAddr(first)
		case s.header == forwardedFor:
			last := lines[len(lines)-1]
			return parseAddr(last[strings.LastIndexByte(last, ',')+1:])
		case len(lines) == 1:
			return parseAddr(lines[0])
		default:
			return netip.Addr{}
		}
	}
	if len(s.proxies) == 0 || !s.trusted(parseAddr(r.RemoteAddr)) {
		return netip.Addr{}
	}
	lines := r.Header.Values(forwardedFor)
	hops := 0
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		for {
			if hops == maxForwardedHops {
				// The trust boundary is still unknown. Use the peer instead
				// of scanning a potentially unbounded chain.
				return netip.Addr{}
			}
			hops++
			comma := strings.LastIndexByte(line, ',')
			hop := parseAddr(line[comma+1:])
			// A malformed hop does not establish that the next hop to its
			// left was added by a proxy. Do not cross it.
			if !hop.IsValid() || !s.trusted(hop) {
				return hop
			}
			if comma < 0 {
				break
			}
			line = line[:comma]
		}
	}
	return netip.Addr{}
}

func (s Source) trusted(a netip.Addr) bool {
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseAddr(value string) netip.Addr {
	// Avoid parsing (and allocating errors or zone strings for) oversized
	// values. Ordinary addresses and ports fit with room for padding and zones.
	if len(value) > maxAddressBytes {
		return netip.Addr{}
	}
	value = strings.TrimSpace(value)
	// netip permits arbitrary zone text, including list separators. A
	// single-address header must not silently accept an address list.
	if strings.ContainsAny(value, ", \t\r\n") {
		return netip.Addr{}
	}
	if ap, err := netip.ParseAddrPort(value); err == nil {
		a := ap.Addr()
		if strings.ContainsAny(a.Zone(), "[]") {
			return netip.Addr{}
		}
		return a.WithZone("").Unmap()
	}
	if len(value) >= 2 && value[0] == '[' && value[len(value)-1] == ']' {
		value = value[1 : len(value)-1]
	}
	// In particular do not turn a broken bracket or port into zone text.
	if strings.ContainsAny(value, "[]") {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range []byte(name) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}
