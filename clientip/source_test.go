package clientip_test

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/17xande-dev/ratelimit/clientip"
)

func TestSource(t *testing.T) {
	const (
		proxy = "10.0.0.1:1234"
		peer  = "203.0.113.7:54321"
		xff   = "X-Forwarded-For"
		cf    = "CF-Connecting-IP"
	)
	modes := map[string]clientip.Source{"zero": {}}
	for _, name := range []string{"remote", "forwarded", "cloudflare", "  cloudflare  "} {
		src, err := clientip.ParseSource(name)
		if err != nil {
			t.Fatal(err)
		}
		modes[name] = src
	}
	for name, cfg := range map[string]clientip.Config{
		"chain":  {TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		"subnet": {TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/25")}},
		"append": {TrustedHeader: "x-forwarded-for"},
		"single": {TrustedHeader: " x-real-ip "},
	} {
		src, err := clientip.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		modes[name] = src
	}
	for _, tc := range []struct {
		name, mode, peer string
		xff, cf, real    []string
		want             string
		fromHeader       bool
	}{
		{name: "zero ignores both headers", mode: "zero", peer: proxy, xff: []string{"192.0.2.50"}, cf: []string{"198.51.100.7"}, want: "10.0.0.1"},
		{name: "remote ignores both headers", mode: "remote", peer: peer, xff: []string{"192.0.2.50"}, cf: []string{"198.51.100.7"}, want: "203.0.113.7"},
		{name: "untrusted peer cannot claim a header", mode: "chain", peer: peer, xff: []string{"192.0.2.50"}, cf: []string{"198.51.100.7"}, want: "203.0.113.7"},
		{name: "CIDRs never enable a second header", mode: "chain", peer: proxy, xff: []string{"192.0.2.50"}, cf: []string{"198.51.100.7"}, want: "192.0.2.50", fromHeader: true},
		{name: "trusted chain", mode: "chain", peer: proxy, xff: []string{"192.0.2.50, 10.0.0.2"}, want: "192.0.2.50", fromHeader: true},
		{name: "rightmost untrusted hop, not client claim", mode: "chain", peer: proxy, xff: []string{"198.51.100.7:80, 192.0.2.50:4000, 10.0.0.2:1"}, want: "192.0.2.50", fromHeader: true},
		{name: "IPv6 hop with port", mode: "chain", peer: proxy, xff: []string{"198.51.100.7, [2001:db8::5]:4444"}, want: "2001:db8::5", fromHeader: true},
		{name: "malformed hop is not crossed", mode: "chain", peer: proxy, xff: []string{"192.0.2.50, junk, 10.0.0.2"}, want: "10.0.0.1"},
		{name: "empty hop is not crossed", mode: "chain", peer: proxy, xff: []string{"192.0.2.50, , 10.0.0.2"}, want: "10.0.0.1"},
		{name: "all hops trusted", mode: "chain", peer: proxy, xff: []string{"10.0.0.2, 10.0.0.3"}, want: "10.0.0.1"},
		{name: "no XFF", mode: "chain", peer: proxy, cf: []string{"198.51.100.7"}, want: "10.0.0.1"},
		{name: "multiple lines are one chain", mode: "chain", peer: proxy, xff: []string{"198.51.100.7", "192.0.2.50, 10.0.0.2"}, want: "192.0.2.50", fromHeader: true},
		{name: "chain continues across lines", mode: "chain", peer: proxy, xff: []string{"192.0.2.50", "10.0.0.2"}, want: "192.0.2.50", fromHeader: true},
		{name: "inside configured subnet", mode: "subnet", peer: "192.0.2.126:1", xff: []string{"198.51.100.7"}, want: "198.51.100.7", fromHeader: true},
		{name: "outside configured subnet", mode: "subnet", peer: "192.0.2.129:1", xff: []string{"198.51.100.7"}, want: "192.0.2.129"},
		{name: "forwarded uses first entry of replacement", mode: "forwarded", peer: peer, xff: []string{" 192.0.2.50:51234 , 10.0.0.1, 10.0.0.2"}, cf: []string{"198.51.100.7"}, want: "192.0.2.50", fromHeader: true},
		{name: "forwarded first line", mode: "forwarded", peer: peer, xff: []string{"192.0.2.50", "198.51.100.7"}, want: "192.0.2.50", fromHeader: true},
		{name: "forwarded with no header ignores CF", mode: "forwarded", peer: peer, cf: []string{"198.51.100.7"}, want: "203.0.113.7"},
		{name: "forwarded empty first entry", mode: "forwarded", peer: peer, xff: []string{"  , 192.0.2.50"}, want: "203.0.113.7"},
		{name: "forwarded invalid first entry", mode: "forwarded", peer: peer, xff: []string{"junk, 192.0.2.50"}, want: "203.0.113.7"},
		{name: "forwarded bracketed IPv6 port", mode: "forwarded", peer: peer, xff: []string{"[2001:db8::1]:51234"}, want: "2001:db8::1", fromHeader: true},
		{name: "forwarded bare IPv6", mode: "forwarded", peer: peer, xff: []string{"2001:db8::1"}, want: "2001:db8::1", fromHeader: true},
		{name: "forwarded bracketed IPv6 without port", mode: "forwarded", peer: peer, xff: []string{"[2001:db8::2]"}, want: "2001:db8::2", fromHeader: true},
		{name: "cloudflare ignores XFF", mode: "cloudflare", peer: peer, cf: []string{" 192.0.2.50:51234 "}, xff: []string{"198.51.100.7"}, want: "192.0.2.50", fromHeader: true},
		{name: "cloudflare never falls back to XFF", mode: "cloudflare", peer: peer, xff: []string{"198.51.100.7"}, want: "203.0.113.7"},
		{name: "empty CF", mode: "cloudflare", peer: peer, cf: []string{"   "}, want: "203.0.113.7"},
		{name: "invalid CF", mode: "cloudflare", peer: peer, cf: []string{"not-an-ip:80"}, want: "203.0.113.7"},
		{name: "duplicate CF", mode: "cloudflare", peer: peer, cf: []string{"192.0.2.50", "198.51.100.7"}, want: "203.0.113.7"},
		{name: "CF address list", mode: "cloudflare", peer: peer, cf: []string{"fe80::1%zone,192.0.2.50"}, want: "203.0.113.7"},
		{name: "CF bracketed IPv6 port", mode: "  cloudflare  ", peer: peer, cf: []string{"[2001:db8::1]:443"}, want: "2001:db8::1", fromHeader: true},
		{name: "CF bare IPv6", mode: "cloudflare", peer: peer, cf: []string{"2001:db8::3"}, want: "2001:db8::3", fromHeader: true},
		{name: "CF bracketed IPv6 without port", mode: "cloudflare", peer: peer, cf: []string{"[2001:db8::7]"}, want: "2001:db8::7", fromHeader: true},
		{name: "CF port range", mode: "cloudflare", peer: peer, cf: []string{"192.0.2.50:65536"}, want: "203.0.113.7"},
		{name: "append takes rightmost", mode: "append", peer: proxy, xff: []string{"198.51.100.7, 10.0.0.7"}, want: "10.0.0.7", fromHeader: true},
		{name: "append takes rightmost line and entry with port", mode: "append", peer: proxy, xff: []string{"198.51.100.7, 198.51.100.8", "198.51.100.9, 192.0.2.50:4443"}, want: "192.0.2.50", fromHeader: true},
		{name: "append last line only", mode: "append", peer: proxy, xff: []string{"198.51.100.7", "192.0.2.50"}, want: "192.0.2.50", fromHeader: true},
		{name: "append malformed last entry", mode: "append", peer: proxy, xff: []string{"192.0.2.50, junk"}, want: "10.0.0.1"},
		{name: "append IPv6 with port", mode: "append", peer: proxy, xff: []string{"[2001:db8::1]:4711"}, want: "2001:db8::1", fromHeader: true},
		{name: "append IPv6 without port", mode: "append", peer: proxy, xff: []string{"[2001:db8::1]"}, want: "2001:db8::1", fromHeader: true},
		{name: "append bare IPv6", mode: "append", peer: proxy, xff: []string{"2001:db8::1"}, want: "2001:db8::1", fromHeader: true},
		{name: "custom single header", mode: "single", peer: proxy, cf: []string{"198.51.100.7"}, real: []string{"192.0.2.50"}, want: "192.0.2.50", fromHeader: true},
		{name: "bracketed IPv6 peer", mode: "zero", peer: "[2001:db8::7]:99", want: "2001:db8::7"},
		{name: "bare peer", mode: "zero", peer: "203.0.113.9", want: "203.0.113.9"},
		{name: "bad peer yields invalid address", mode: "chain", peer: "not-an-ip", xff: []string{"192.0.2.50"}},
		{name: "zoned peer normalised", mode: "zero", peer: "[fe80::1%eth0]:1234", want: "fe80::1"},
		{name: "zoned header normalised", mode: "cloudflare", peer: proxy, cf: []string{"[fe80::1%eth1]:443"}, want: "fe80::1", fromHeader: true},
		{name: "malformed bracket is not a zone", mode: "cloudflare", peer: proxy, cf: []string{"[fe80::1%eth1]]:443"}, want: "10.0.0.1"},
		{name: "mapped header normalised", mode: "cloudflare", peer: proxy, cf: []string{"[::ffff:192.0.2.50]:443"}, want: "192.0.2.50", fromHeader: true},
		{name: "mapped peer and hop match IPv4 CIDR", mode: "chain", peer: "[::ffff:10.0.0.1]:1234", xff: []string{"192.0.2.50, ::ffff:10.0.0.2"}, want: "192.0.2.50", fromHeader: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tc.peer, Header: http.Header{}}
			for key, values := range map[string][]string{xff: tc.xff, cf: tc.cf, "X-Real-IP": tc.real} {
				for _, value := range values {
					r.Header.Add(key, value)
				}
			}
			var want netip.Addr
			if tc.want != "" {
				want = netip.MustParseAddr(tc.want)
			}
			src := modes[tc.mode]
			if got := src.Addr(r); got != want {
				t.Errorf("Addr = %s, want %s", got, want)
			}
			var wantHeader netip.Addr
			if tc.fromHeader {
				wantHeader = want
			}
			if got := src.HeaderAddr(r); got != wantHeader {
				t.Errorf("HeaderAddr = %s, want %s", got, wantHeader)
			}
		})
	}
}

func TestNewRejectsInvalidPolicy(t *testing.T) {
	for name, cfg := range map[string]clientip.Config{
		"two policies": {TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, TrustedHeader: "CF-Connecting-IP"},
		"bad prefix":   {TrustedProxies: []netip.Prefix{{}}},
		"wide mapped":  {TrustedProxies: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/95")}},
		"bad header":   {TrustedHeader: "X-Real-IP:"},
		"blank header": {TrustedHeader: " "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := clientip.New(cfg); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestNewCopiesMappedProxyPrefixes(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.9/104")}
	src, err := clientip.New(clientip.Config{TrustedProxies: prefixes})
	if err != nil {
		t.Fatal(err)
	}
	prefixes[0] = netip.MustParsePrefix("192.0.2.0/24")
	r := &http.Request{RemoteAddr: "10.0.0.2:443", Header: http.Header{"X-Forwarded-For": {"198.51.100.1"}}}
	if got := src.Addr(r); got != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("Addr = %s, want 198.51.100.1", got)
	}
}

func TestNewRejectsWildcardTrust(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96"} {
		t.Run(prefix, func(t *testing.T) {
			_, err := clientip.New(clientip.Config{TrustedProxies: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.0/24"),
				netip.MustParsePrefix(prefix),
			}})
			if err == nil || !strings.Contains(err.Error(), "/0") {
				t.Errorf("New with %s = %v, want an explicit /0 refusal", prefix, err)
			}
		})
	}
}

func TestTrustedChainHopLimit(t *testing.T) {
	src, err := clientip.New(clientip.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	const untrusted = "192.0.2.50"
	const trusted = ", 10.0.0.2"
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{"64th is untrusted", []string{untrusted + strings.Repeat(trusted, 63)}, untrusted},
		{"65th is untrusted", []string{untrusted + strings.Repeat(trusted, 64)}, "10.0.0.1"},
		{"limit spans lines", []string{untrusted, strings.TrimPrefix(strings.Repeat(trusted, 64), ", ")}, "10.0.0.1"},
		{"large unneeded prefix", []string{untrusted + strings.Repeat(trusted, 1<<17) + ", " + untrusted}, untrusted},
		{"large all-trusted suffix", []string{untrusted + strings.Repeat(trusted, 1<<17)}, "10.0.0.1"},
		{"oversized individual hop", []string{untrusted + ", fe80::1%" + strings.Repeat("x", 1<<20)}, "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: "10.0.0.1:443", Header: http.Header{"X-Forwarded-For": tc.lines}}
			if got := src.Addr(r); got != netip.MustParseAddr(tc.want) {
				t.Errorf("Addr = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestParseSourceRejectsUnknownModes(t *testing.T) {
	for _, value := range []string{"", "cloudlfare", "Cloudflare", "true", "xff", "trust-everyone"} {
		src, err := clientip.ParseSource(value)
		if err == nil {
			t.Errorf("ParseSource(%q) succeeded", value)
		}
		r := &http.Request{RemoteAddr: "192.0.2.3:123", Header: http.Header{"X-Forwarded-For": {"198.51.100.1"}}}
		if got := src.Addr(r); got != netip.MustParseAddr("192.0.2.3") {
			t.Errorf("invalid policy read unexpected address %s", got)
		}
	}
}
