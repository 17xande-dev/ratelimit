package ratelimit

import (
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/17xande-dev/ratelimit/clientip"
)

// IPKey keeps each IPv4 address separate and groups IPv6 addresses by /64.
// An invalid address shares one key rather than creating arbitrary buckets.
func IPKey(addr netip.Addr) string {
	addr = addr.WithZone("").Unmap()
	switch {
	case addr.Is4():
		return addr.String()
	case addr.Is6():
		prefix, _ := addr.Prefix(64)
		return prefix.String()
	default:
		return "unknown"
	}
}

// HTTPOptions controls the middleware's response to a refused request.
type HTTPOptions struct {
	// RetryAfter is an optional, fixed hint rounded up to whole seconds.
	// Nonpositive values omit it. In particular, capacity refusals need not
	// clear after this interval.
	RetryAfter time.Duration
	// Exceeded writes the rejection, including its status. The default
	// writes a plain-text 429. Retry-After is set before calling this hook.
	Exceeded http.Handler
}

// Middleware wraps handlers with a per-IP limit. Wrappers built from the same
// limiter share its buckets; use a separate limiter for each independent tier.
// Calling Middleware on a nil limiter panics at setup time.
func (l *Limiter) Middleware(source clientip.Source, opts HTTPOptions) func(http.Handler) http.Handler {
	if l == nil {
		panic("ratelimit: nil limiter passed to Middleware")
	}
	var retryAfter string
	if opts.RetryAfter > 0 {
		retryAfter = strconv.FormatInt(int64((opts.RetryAfter-1)/time.Second)+1, 10)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l.Allow(IPKey(source.Addr(r))) {
				next.ServeHTTP(w, r)
				return
			}
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			if opts.Exceeded != nil {
				opts.Exceeded.ServeHTTP(w, r)
				return
			}
			http.Error(w, "too many requests", http.StatusTooManyRequests)
		})
	}
}
