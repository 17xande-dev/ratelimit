# ratelimit

Bounded, process-local token buckets for Go HTTP handlers and application keys.
The module uses `golang.org/x/time/rate` for token accounting. The `clientip`
subpackage uses only the standard library and can be used independently.

## Per-IP limit

```go
import (
    "time"

    "github.com/17xande-dev/ratelimit"
    "github.com/17xande-dev/ratelimit/clientip"
    "golang.org/x/time/rate"
)

// In startup code that returns an error:
ipLimit, err := ratelimit.New(ratelimit.Config{
    Rate:  rate.Every(10 * time.Second),
    Burst: 5,
})
if err != nil {
    return err
}
mux.Handle("POST /login", ipLimit.Middleware(clientip.Source{}, ratelimit.HTTPOptions{
    RetryAfter: 10 * time.Second,
})(login))
```

The zero `clientip.Source` uses only the socket peer. IPv4 gets one bucket per
address and IPv6 gets one per /64. An invalid address shares one `"unknown"`
bucket. By default the middleware answers with a plain-text 429. `RetryAfter`
is an optional fixed hint, rounded up to whole seconds, not a promise that a
full table will have room by then. `Exceeded` can write a custom 429; the
middleware sets the retry hint before invoking it.

## Behind a proxy

Select the policy that matches what the ingress actually does. A header-based
policy is not a check on the socket peer. Use it only when clients cannot
bypass the ingress or control the part of the header being read.

| Configuration | Address used |
| --- | --- |
| Zero `Source` or `ParseSource("remote")` | The socket peer. |
| `New(Config{TrustedProxies: prefixes})` | Only for a peer in a trusted CIDR: scan `X-Forwarded-For` from right to left across all lines and stop at the first untrusted hop. |
| `New(Config{TrustedHeader: "X-Forwarded-For"})` | Rightmost item of the last line, for an ingress that appends the observed client. |
| `ParseSource("forwarded")` | Leftmost item of the first line, preserving the named mode for an ingress that **replaces** all incoming copies. Never use it with an appending ingress. |
| `New(Config{TrustedHeader: "X-Real-IP"})` | One value on one line, for an ingress that overwrites the header. |
| `ParseSource("cloudflare")` | One `CF-Connecting-IP` value on one line. Cloudflare must be the sole ingress; there is no XFF fallback. |

For example, to trust an append chain from a controlled proxy network:

```go
source, err := clientip.New(clientip.Config{
    TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28")},
})
```

Check the configuration error before serving. CIDRs and a trusted header are
mutually exclusive. CIDR mode **does not also honour `CF-Connecting-IP`**;
verify ingress behaviour before replacing a resolver that read both. Prefer
peer-only or CIDR mode when direct connections are possible. A missing or
malformed selected address, repeated single-value header, untrusted peer in
CIDR mode, or chain with no untrusted hop falls back to the peer. The CIDR
scan never skips a malformed hop to reach an earlier value.

`Source.Addr` returns a `netip.Addr`, not a bucket key. IPv4 and bracketed IPv6
ports are stripped, IPv6 zones are removed, and mapped IPv4 is unmapped. Use
`ratelimit.IPKey` to group IPv6 by /64; do not use the resulting prefix in
place of an address for logging or authorization. `Source.HeaderAddr` reports
only the usable header address under the configured policy, or an invalid
address rather than the peer. A valid result is not independent proof of
ingress provenance.

## Per-account or other second tier

Use a separate limiter for each tier. Check the IP tier first, then call
`Allow` with the application-normalised identifier once the request reaches
the protected operation:

```go
if !accountLimit.Allow(normalizedAccount) {
    http.Error(w, "too many requests", http.StatusTooManyRequests)
    return
}
```

Oversized keys are refused, not truncated or hashed. Apply existing input
validation and user-facing responses before this check if they should remain
unchanged. For failure-only accounting, `Exhausted` tests without consuming a
token or inserting a key. An `Exhausted` check followed by `Allow` after a
failure is not atomic; concurrent failures can pass the check together.

## Memory and overflow

Each limiter holds at most `MaxKeys` buckets (default 10,000). Each retained
key holds at most `MaxKeyBytes` bytes (default 256), copied so a short substring
cannot retain a large request allocation. That bounds default key payloads to
2,560,000 bytes per limiter, plus map storage, bucket objects and allocator
overhead. This limit is per process, not shared across replicas.

Sweeps run on use after an idle interval (default ten minutes) or when a new
key finds the table full, at most once every five seconds. There is no
background goroutine. A bucket must be both idle and fully refilled before it
can be removed. If the table is still full, an untracked key is denied by
default; existing keys still use their own buckets. `FailOpenWhenFull` instead
admits untracked keys without storing them. Reserve it for best-effort traffic
limits, never for credential checks.

Run `make fmt-check vet test vulncheck` before committing. The test target
enables the race detector; clock-dependent tests advance an injected clock
instead of sleeping.
