package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/17xande-dev/ratelimit/clientip"
)

func TestIPKey(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:1111:2222:3333:4444", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"fe80::1%eth0", "fe80::/64"},
		{"fe80::1%eth1", "fe80::/64"},
		{"fe80::2", "fe80::/64"},
		{"junk", "unknown"},
	} {
		a, _ := netip.ParseAddr(tc.in)
		if got := IPKey(a); got != tc.want {
			t.Errorf("IPKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMiddlewareBuckets(t *testing.T) {
	for _, tc := range []struct {
		name, source, header string
		peers, values        []string
		want                 []int
	}{
		{"IPv6 peers share a /64", "remote", "", []string{"[2001:db8:1:2::1]:1", "[2001:db8:1:2::2]:2", "[2001:db8:1:3::1]:3"}, nil, []int{204, 429, 204}},
		{"mapped IPv4 shares its bucket", "remote", "", []string{"192.0.2.7:1", "[::ffff:192.0.2.7]:2", "192.0.2.8:3"}, nil, []int{204, 429, 204}},
		{"malformed peers share a bucket", "remote", "", []string{"bad peer", "other bad peer"}, nil, []int{204, 429}},
		{"remote does not trust XFF", "remote", "X-Forwarded-For", []string{"192.0.2.7:1", "192.0.2.7:2"}, []string{"198.51.100.1", "198.51.100.2"}, []int{204, 429}},
		{"replaced XFF identifies each client", "forwarded", "X-Forwarded-For", []string{"192.0.2.7:1", "192.0.2.7:2", "192.0.2.7:3"}, []string{"198.51.100.1", "198.51.100.2", "198.51.100.1:443"}, []int{204, 204, 429}},
		{"CF identifies each client", "cloudflare", "CF-Connecting-IP", []string{"192.0.2.7:1", "192.0.2.7:2", "192.0.2.7:3"}, []string{"198.51.100.1", "198.51.100.2", "198.51.100.1"}, []int{204, 204, 429}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := clientip.ParseSource(tc.source)
			if err != nil {
				t.Fatal(err)
			}
			l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1})
			h := l.Middleware(s, HTTPOptions{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			for i, peer := range tc.peers {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.RemoteAddr = peer
				if tc.header != "" {
					r.Header.Set(tc.header, tc.values[i])
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != tc.want[i] || w.Header().Get("Retry-After") != "" {
					t.Errorf("request %d: got %d with headers %v, want %d without Retry-After", i, w.Code, w.Header(), tc.want[i])
				}
			}
		})
	}
}

func TestMiddlewareTrustsOnlyConfiguredProxyPeers(t *testing.T) {
	source, err := clientip.New(clientip.Config{
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1})
	h := l.Middleware(source, HTTPOptions{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		peer, xff string
		status    int
	}{
		{"192.0.2.1:1", "203.0.113.1", 204},
		{"192.0.2.1:2", "203.0.113.2", 429},
		{"10.0.0.2:1", "203.0.113.1, 198.51.100.1, 10.0.0.3", 204},
		{"10.0.0.2:2", "203.0.113.2, 198.51.100.1, 10.0.0.3", 429},
		{"10.0.0.2:3", "203.0.113.1, 198.51.100.2, 10.0.0.3", 204},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", tc.xff)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("peer %q and XFF %q: got %d, want %d", tc.peer, tc.xff, w.Code, tc.status)
		}
	}
}

func TestMiddlewareOverflowUsesCustomResponse(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 1, IdleTTL: time.Minute})
	nextCalls, exceededCalls := 0, 0
	h := l.Middleware(clientip.Source{}, HTTPOptions{
		RetryAfter: 1500 * time.Millisecond,
		Exceeded: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			exceededCalls++
			if got := w.Header().Get("Retry-After"); got != "2" {
				t.Errorf("Retry-After in hook = %q, want 2", got)
			}
			http.Error(w, "requested "+r.URL.Path, http.StatusTooManyRequests)
		}),
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		peer string
		code int
		wait time.Duration
	}{
		{"192.0.2.7:1", 204, 0},
		{"192.0.2.8:1", 429, 0},
		{"192.0.2.7:2", 429, 0},
		{"192.0.2.7:2", 204, time.Second},
	} {
		advance(tc.wait)
		r := httptest.NewRequest(http.MethodGet, "/endpoint", nil)
		r.RemoteAddr = tc.peer
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Errorf("%s got %d, want %d", tc.peer, w.Code, tc.code)
		}
		if tc.code == 429 && (w.Result().Header.Get("Retry-After") != "2" || w.Body.String() != "requested /endpoint\n") {
			t.Error("429 response lost its retry hint or hook body")
		}
	}
	if nextCalls != 2 || exceededCalls != 2 {
		t.Errorf("calls: next=%d, exceeded=%d, both should be 2", nextCalls, exceededCalls)
	}
}

func TestMiddlewareRetryAfterRounding(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint time.Duration
		want string
	}{
		{"below", time.Second - time.Nanosecond, "1"},
		{"exact", time.Second, "1"},
		{"above", time.Second + time.Nanosecond, "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l Limiter
			h := l.Middleware(clientip.Source{}, HTTPOptions{RetryAfter: tc.hint})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("zero limiter let request through")
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
			if got := w.Header().Get("Retry-After"); w.Code != http.StatusTooManyRequests || got != tc.want {
				t.Errorf("status = %d, Retry-After = %q; want 429 and %q", w.Code, got, tc.want)
			}
		})
	}
}

func TestNilLimiterMiddlewarePanicsAtSetup(t *testing.T) {
	defer func() {
		if got := recover(); got != "ratelimit: nil limiter passed to Middleware" {
			t.Errorf("setup panic = %v; want an explicit nil limiter error", got)
		}
	}()
	var l *Limiter
	l.Middleware(clientip.Source{}, HTTPOptions{})
}
