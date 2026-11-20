// Package ratelimit provides process-local token buckets with bounded storage.
package ratelimit

import (
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultMaxKeys     = 10_000
	defaultMaxKeyBytes = 256
	defaultIdleTTL     = 10 * time.Minute
	sweepGap           = 5 * time.Second
)

// Config sets a limiter's refill rate, burst and storage policy.
type Config struct {
	Rate  rate.Limit // tokens per second; must be positive and finite
	Burst int        // initial and maximum tokens per key; must be positive

	MaxKeys     int           // zero means 10,000
	MaxKeyBytes int           // zero means 256
	IdleTTL     time.Duration // zero means 10 minutes

	// FailOpenWhenFull admits new keys without tracking them if no room can be
	// freed. Never enable this for a security-sensitive limit.
	FailOpenWhenFull bool

	// Now supplies nondecreasing time. Nil means time.Now. The limiter calls
	// it under its lock; it must not call back into the limiter.
	Now func() time.Time
}

// Limiter is a concurrent keyed token bucket. Use New to construct it.
// Do not copy a Limiter after first use. Its zero value denies requests.
type Limiter struct {
	cfg Config

	mu            sync.Mutex
	buckets       map[string]*bucket
	nextSweep     time.Time
	nextIdleSweep time.Time
}

type bucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

// New creates a limiter. It starts no background goroutine.
func New(cfg Config) (*Limiter, error) {
	if cfg.Rate <= 0 || cfg.Rate >= rate.Inf || math.IsNaN(float64(cfg.Rate)) || cfg.Burst <= 0 {
		return nil, errors.New("ratelimit: need a positive finite rate and positive burst")
	}
	if cfg.MaxKeys < 0 || cfg.MaxKeyBytes < 0 || cfg.IdleTTL < 0 {
		return nil, errors.New("ratelimit: storage bounds must not be negative")
	}
	if cfg.MaxKeys == 0 {
		cfg.MaxKeys = defaultMaxKeys
	}
	if cfg.MaxKeyBytes == 0 {
		cfg.MaxKeyBytes = defaultMaxKeyBytes
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Limiter{cfg: cfg, buckets: make(map[string]*bucket)}, nil
}

// Allow spends a token for key if one is available. An oversized key is
// refused, even in fail-open mode. A full table refuses untracked keys unless
// FailOpenWhenFull was explicitly set.
func (l *Limiter) Allow(key string) bool {
	return l.check(key, true)
}

// Exhausted reports whether a key's attempt would be refused, without spending
// a token or tracking a new key. A later Allow is a separate decision: another
// goroutine may consume a token or fill the table in between.
func (l *Limiter) Exhausted(key string) bool {
	return !l.check(key, false)
}

func (l *Limiter) check(key string, spend bool) bool {
	if l.cfg.Now == nil || len(key) > l.cfg.MaxKeyBytes {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.cfg.Now()
	if len(l.buckets) != 0 && !now.Before(l.nextIdleSweep) {
		l.sweep(now)
	}

	b, exists := l.buckets[key]
	if !exists {
		if len(l.buckets) >= l.cfg.MaxKeys {
			l.sweep(now)
			if len(l.buckets) >= l.cfg.MaxKeys {
				return l.cfg.FailOpenWhenFull
			}
		}
		if !spend {
			return true
		}
		if len(l.buckets) == 0 {
			l.nextIdleSweep = now.Add(l.cfg.IdleTTL)
		}
		b = &bucket{limiter: rate.NewLimiter(l.cfg.Rate, l.cfg.Burst)}
		// A short substring could otherwise retain a large request buffer.
		l.buckets[strings.Clone(key)] = b
	}
	if !spend {
		return b.limiter.TokensAt(now) >= 1
	}
	b.seen = now
	return b.limiter.AllowN(now, 1)
}

// sweep runs under the same lock as lookups and token decisions: a request
// can't keep using an old bucket after a sweep has admitted its replacement.
func (l *Limiter) sweep(now time.Time) {
	if !l.nextSweep.IsZero() && now.Before(l.nextSweep) {
		return
	}
	l.nextSweep = now.Add(sweepGap)
	l.nextIdleSweep = now.Add(l.cfg.IdleTTL)
	for key, b := range l.buckets {
		// Eviction must not give a partly refilled bucket a fresh burst,
		// even when the configured idle lifetime is short for its rate.
		if now.Sub(b.seen) >= l.cfg.IdleTTL && b.limiter.TokensAt(now) >= float64(l.cfg.Burst) {
			delete(l.buckets, key)
		}
	}
}
