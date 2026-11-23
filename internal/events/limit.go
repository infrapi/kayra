package events

import (
	"math"
	"sync"
	"time"
)

// limiter is a token bucket per reporter: perSecond tokens, burst at most.
type limiter struct {
	perSecond float64
	burst     float64
	now       func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perSecond float64, burst int, now func() time.Time) *limiter {
	return &limiter{perSecond: perSecond, burst: float64(burst), now: now, buckets: map[string]*bucket{}}
}

// take takes n tokens of reporter's bucket, or tells how long to wait for
// them.
func (l *limiter) take(reporter string, n int) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, found := l.buckets[reporter]
	if !found {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[reporter] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.perSecond)
	b.last = now
	need := math.Min(float64(n), l.burst) // a batch over the burst waits for a full bucket
	if b.tokens >= need {
		b.tokens -= need
		return true, 0
	}
	wait := time.Duration((need - b.tokens) / l.perSecond * float64(time.Second))
	return false, max(wait, time.Second)
}
