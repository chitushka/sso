package middleware

import (
	"container/list"
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/chitushka/sso/internal/httpx"
)

const defaultMaxRateLimitBuckets = 10_000

// RateLimiter определяет, можно ли выполнить запрос с указанным ключом.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}

type bucket struct {
	key      string
	tokens   float64
	lastSeen time.Time
	element  *list.Element
}

type RateLimitStats struct {
	Buckets           int
	TTLEvictions      uint64
	CapacityEvictions uint64
}

// TokenBucketLimiter пополняет rate токенов в секунду до burst для каждого
// ключа. LRU-список обеспечивает амортизированное O(1)-вытеснение и жёсткий
// предел памяти даже при потоке уникальных IP-адресов.
type TokenBucketLimiter struct {
	mu                sync.Mutex
	buckets           map[string]*bucket
	lru               *list.List
	rate              float64
	burst             float64
	ttl               time.Duration
	maxBuckets        int
	now               func() time.Time
	ttlEvictions      uint64
	capacityEvictions uint64
}

func NewTokenBucketLimiter(ratePerMinute, burst int) *TokenBucketLimiter {
	return newTokenBucketLimiter(ratePerMinute, burst, defaultMaxRateLimitBuckets, time.Now)
}

func newTokenBucketLimiter(ratePerMinute, burst, maxBuckets int, now func() time.Time) *TokenBucketLimiter {
	if ratePerMinute <= 0 || burst <= 0 || maxBuckets <= 0 {
		panic("параметры rate limiter должны быть положительными")
	}
	rate := float64(ratePerMinute) / 60
	return &TokenBucketLimiter{
		buckets:    make(map[string]*bucket, maxBuckets),
		lru:        list.New(),
		rate:       rate,
		burst:      float64(burst),
		ttl:        time.Duration(float64(time.Second) * float64(burst) / rate),
		maxBuckets: maxBuckets,
		now:        now,
	}
}

func (l *TokenBucketLimiter) Allow(_ context.Context, key string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		l.evictExpired(now)
		if len(l.buckets) >= l.maxBuckets {
			l.remove(l.lru.Back())
			l.capacityEvictions++
		}
		b = &bucket{key: key, tokens: l.burst - 1, lastSeen: now}
		b.element = l.lru.PushFront(b)
		l.buckets[key] = b
		return true, nil
	}
	b.tokens += now.Sub(b.lastSeen).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now
	l.lru.MoveToFront(b.element)
	if b.tokens < 1 {
		return false, nil
	}
	b.tokens--
	return true, nil
}

func (l *TokenBucketLimiter) evictExpired(now time.Time) {
	for element := l.lru.Back(); element != nil; element = l.lru.Back() {
		b := element.Value.(*bucket)
		if now.Sub(b.lastSeen) < l.ttl {
			return
		}
		l.remove(element)
		l.ttlEvictions++
	}
}

func (l *TokenBucketLimiter) remove(element *list.Element) {
	if element == nil {
		return
	}
	b := element.Value.(*bucket)
	delete(l.buckets, b.key)
	l.lru.Remove(element)
}

func (l *TokenBucketLimiter) Stats() RateLimitStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return RateLimitStats{Buckets: len(l.buckets), TTLEvictions: l.ttlEvictions, CapacityEvictions: l.capacityEvictions}
}

type LayeredRateLimiter struct{ limiters []RateLimiter }

func NewLayeredRateLimiter(limiters ...RateLimiter) *LayeredRateLimiter {
	return &LayeredRateLimiter{limiters: limiters}
}

func (l *LayeredRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	for _, limiter := range l.limiters {
		allowed, err := limiter.Allow(ctx, key)
		if err != nil || !allowed {
			return allowed, err
		}
	}
	return true, nil
}

// RateLimit применяет ограничитель к точным путям запросов с ключом IP клиента + путь.
func RateLimit(limiter RateLimiter, paths ...string) func(http.Handler) http.Handler {
	limited := map[string]bool{}
	for _, p := range paths {
		limited[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limited[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			allowed, err := limiter.Allow(r.Context(), httpx.ClientIP(r)+" "+r.URL.Path)
			if err != nil {
				w.Header().Set("Retry-After", "60")
				httpx.Error(w, http.StatusServiceUnavailable, "rate limiter unavailable")
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", "60")
				httpx.Error(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
