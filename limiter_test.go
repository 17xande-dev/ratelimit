package ratelimit

import (
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func newTestLimiter(t *testing.T, cfg Config) (*Limiter, func(time.Duration)) {
	t.Helper()
	var now time.Time
	cfg.Now = func() time.Time { return now }
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l, func(d time.Duration) { now = now.Add(d) }
}

func TestBurstRefillAndIndependentKeys(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: rate.Every(2 * time.Second), Burst: 2})
	first, second := l.Allow("user"), l.Allow("user")
	if !first || !second || l.Allow("user") || !l.Allow("other") {
		t.Fatal("burst is not independent per key")
	}
	advance(2*time.Second - time.Nanosecond)
	if l.Allow("user") {
		t.Fatal("allowed before one token accrued")
	}
	advance(time.Nanosecond)
	if !l.Allow("user") || l.Allow("user") {
		t.Fatal("one new token should be available at the refill boundary")
	}
}

func TestCapacityAndEviction(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 2, IdleTTL: time.Minute})
	if !l.Allow("idle") || !l.Allow("live") || l.Allow("new") {
		t.Fatal("expected a full table to refuse new keys")
	}
	advance(time.Minute - time.Second)
	if !l.Allow("live") {
		t.Fatal("full table should not refuse a tracked key with a token")
	}
	advance(time.Second)
	if !l.Allow("new") {
		t.Fatal("new key should be admitted once an idle key is swept")
	}
	if len(l.buckets) != 2 || l.buckets["idle"] != nil || l.buckets["live"] == nil {
		t.Fatal("sweep did not reclaim only the idle entry")
	}
}

func TestDefaultCapacity(t *testing.T) {
	l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1})
	for i := range 10_000 {
		if !l.Allow(strconv.Itoa(i)) {
			t.Fatalf("default limiter refused key %d before reaching its cap", i)
		}
	}
	for i := 10_000; i < 10_100; i++ {
		if l.Allow(strconv.Itoa(i)) {
			t.Fatalf("default limiter admitted key %d beyond its cap", i)
		}
	}
	if len(l.buckets) != 10_000 {
		t.Fatalf("tracked %d keys, want 10,000", len(l.buckets))
	}
}

func TestCapacityOverflowFailsOpenOnlyForUntrackedKeys(t *testing.T) {
	l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 1, FailOpenWhenFull: true})
	if !l.Allow("tracked") || l.Allow("tracked") {
		t.Fatal("fail-open must not bypass a tracked key's limit")
	}
	for i := range 100 {
		if !l.Allow(strconv.Itoa(i)) {
			t.Fatal("fail-open refused an untracked key")
		}
	}
	if len(l.buckets) != 1 {
		t.Fatal("fail-open let the table grow")
	}
}

func TestOnFullAndLen(t *testing.T) {
	for _, open := range []bool{false, true} {
		t.Run(strconv.FormatBool(open), func(t *testing.T) {
			calls := 0
			l, advance := newTestLimiter(t, Config{
				Rate: 1, Burst: 1, MaxKeys: 1, MaxKeyBytes: 7, FailOpenWhenFull: open, IdleTTL: time.Minute,
				OnFull: func() { calls++ },
			})
			if l.Len() != 0 || !l.Allow("tracked") || l.Len() != 1 {
				t.Fatal("Len did not reflect first insertion")
			}
			if l.Allow("tracked") || l.Allow("oversized") || l.Exhausted("new") == open || calls != 0 {
				t.Fatal("bucket depletion, an oversized key or a probe triggered OnFull")
			}
			for _, key := range []string{"new", "another"} {
				if got := l.Allow(key); got != open {
					t.Errorf("Allow(%q) = %t, want %t", key, got, open)
				}
			}
			wantCalls := 2
			if open {
				wantCalls = 0
			}
			if calls != wantCalls || l.Len() != 1 {
				t.Fatalf("OnFull called %d times, want %d; Len = %d, want 1", calls, wantCalls, l.Len())
			}
			advance(time.Minute)
			if !l.Allow("new") || calls != wantCalls || l.Len() != 1 {
				t.Fatal("reclaimed capacity should admit the new key without calling OnFull")
			}
		})
	}
}

func TestOnFullCanReenterForTrackedKey(t *testing.T) {
	var l *Limiter
	var observed struct {
		len                   int
		exhausted, spentToken bool
	}
	l, _ = newTestLimiter(t, Config{
		Rate: 1, Burst: 2, MaxKeys: 1,
		OnFull: func() {
			observed.len = l.Len()
			observed.exhausted = l.Exhausted("tracked")
			observed.spentToken = l.Allow("tracked")
		},
	})
	if !l.Allow("tracked") {
		t.Fatal("could not seed the tracked key")
	}

	result := make(chan bool, 1)
	go func() { result <- l.Allow("new") }()
	select {
	case allowed := <-result:
		if allowed || observed.len != 1 || observed.exhausted || !observed.spentToken {
			t.Fatalf("new key allowed = %t; within OnFull: %+v", allowed, observed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnFull did not return: callback may be running under the limiter lock")
	}
}

func TestSweepIsThrottledStartingAtZeroTime(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 1, IdleTTL: time.Second})
	if !l.Allow("idle") || l.Allow("new") {
		t.Fatal("expected full table")
	}
	advance(5*time.Second - time.Nanosecond)
	if l.Allow("new") {
		t.Fatal("cap-triggered or periodic sweep ran again before the minimum interval")
	}
	advance(time.Nanosecond)
	if !l.Allow("new") {
		t.Fatal("eligible bucket was not recovered at the sweep boundary")
	}
}

func TestPeriodicSweepBelowCapacity(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 10, IdleTTL: time.Minute})
	if !l.Allow("old") {
		t.Fatal("first request refused")
	}
	advance(time.Minute)
	if !l.Allow("new") || len(l.buckets) != 1 || l.buckets["old"] != nil {
		t.Fatal("periodic sweep did not reclaim the idle key")
	}
}

func TestCapacityTriggersSweepBeforeNextPeriodicSweep(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 2, IdleTTL: time.Minute})
	if !l.Allow("first") {
		t.Fatal("first request refused")
	}
	advance(10 * time.Second)
	if !l.Allow("second") {
		t.Fatal("second request refused")
	}
	advance(50 * time.Second)
	if !l.Allow("third") || l.buckets["first"] != nil {
		t.Fatal("periodic sweep failed to drop the oldest key")
	}
	advance(10 * time.Second)
	if !l.Allow("fourth") || l.buckets["second"] != nil || len(l.buckets) != 2 {
		t.Fatal("capacity did not force a sweep before the next regular sweep")
	}
}

func TestSweepDoesNotRefillEarly(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: rate.Every(10 * time.Second), Burst: 2, MaxKeys: 1, IdleTTL: time.Second})
	for i := range 2 {
		if !l.Allow("slow") {
			t.Fatalf("initial token %d refused", i+1)
		}
	}
	advance(5 * time.Second)
	if l.Allow("new") || !l.Exhausted("slow") {
		t.Fatal("a short TTL discarded a partly refilled bucket")
	}
	advance(15 * time.Second)
	if !l.Allow("new") {
		t.Fatal("fully refilled idle bucket was not reclaimed")
	}
}

func TestKeyLengthUsesBytesAndRejectsWithoutTracking(t *testing.T) {
	for _, open := range []bool{false, true} {
		l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: 1, MaxKeyBytes: 4, FailOpenWhenFull: open})
		if l.Allow("ééa") || !l.Exhausted("ééa") || len(l.buckets) != 0 {
			t.Fatal("oversized multibyte key was not rejected before allocation")
		}
		if !l.Allow("éé") || l.Allow("ééa") || !l.Exhausted("ééa") {
			t.Fatal("key-length boundary or capacity interaction is wrong")
		}
	}
	l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1})
	if !l.Allow(strings.Repeat("x", 256)) || l.Allow(strings.Repeat("y", 257)) {
		t.Fatal("default key length bound is wrong")
	}
}

func TestSubstringKeysDoNotRetainBackingBuffers(t *testing.T) {
	const (
		buffers = 8
		size    = 2 << 20
	)
	l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 1, MaxKeys: buffers})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range buffers {
		buffer := strings.Repeat(strconv.Itoa(i), size)
		if !l.Allow(buffer[:32]) {
			t.Fatalf("key %d refused", i)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if l.Len() != buffers {
		t.Fatalf("tracked %d keys, want %d", l.Len(), buffers)
	}
	// Missing copies retain 16 MiB. Allow half of that for unrelated heap
	// movement rather than assuming exact runtime memory accounting.
	if after.HeapAlloc > before.HeapAlloc+buffers*size/2 {
		t.Fatalf("live heap grew by %d bytes; short keys retained large buffers", after.HeapAlloc-before.HeapAlloc)
	}
}

func TestExhaustedNeverSpendsOrCreates(t *testing.T) {
	l, advance := newTestLimiter(t, Config{Rate: 1, Burst: 2, MaxKeys: 1})
	if l.Exhausted("unknown") || len(l.buckets) != 0 {
		t.Fatal("probing an unseen key should not allocate")
	}
	if !l.Allow("known") || l.Exhausted("known") || !l.Allow("known") || !l.Exhausted("known") {
		t.Fatal("probing a known key must not consume tokens")
	}
	if !l.Exhausted("unknown") || len(l.buckets) != 1 {
		t.Fatal("a probe must report a full fail-closed table")
	}
	advance(time.Second)
	if l.Exhausted("known") {
		t.Fatal("exhaustion check missed a recovered token")
	}
}

func TestConcurrentAllow(t *testing.T) {
	l, _ := newTestLimiter(t, Config{Rate: 1, Burst: 5, MaxKeys: 2})
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := range 300 {
		wg.Go(func() {
			if l.Allow(strconv.Itoa(i % 3)) {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if n := admitted.Load(); n != 10 || l.Len() != 2 {
		t.Fatalf("admitted %d requests with %d keys, want 10 with 2 keys", n, l.Len())
	}
}

func TestInvalidConfigAndZeroLimiter(t *testing.T) {
	for _, cfg := range []Config{
		{Rate: 1}, {Burst: 1}, {Rate: -1, Burst: 1}, {Rate: rate.Inf, Burst: 1},
		{Rate: rate.Limit(math.Inf(1)), Burst: 1}, {Rate: rate.Limit(math.NaN()), Burst: 1},
		{Rate: 1, Burst: 1, MaxKeys: -1}, {Rate: 1, Burst: 1, MaxKeyBytes: -1},
		{Rate: 1, Burst: 1, IdleTTL: -1},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) accepted invalid configuration", cfg)
		}
	}
	var l Limiter
	if l.Allow("key") || !l.Exhausted("key") {
		t.Fatal("zero limiter must deny")
	}
	if l.Allow("") || !l.Exhausted("") || l.Len() != 0 {
		t.Fatal("zero limiter must deny an empty key without tracking it")
	}
}
