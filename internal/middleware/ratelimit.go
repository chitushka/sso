package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chitushka/sso/internal/httpx"
)

// RateLimiter decides whether a request identified by key may proceed.
// The in-memory implementation can be swapped for Redis later.
type RateLimiter interface {
	Allow(key string) bool
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// TokenBucketLimiter refills rate tokens per second up to burst, per key.
type TokenBucketLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64
	burst   float64
}

func NewTokenBucketLimiter(ratePerMinute, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{buckets: map[string]*bucket{}, rate: float64(ratePerMinute) / 60.0, burst: float64(burst)}
}
func (l *TokenBucketLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		l.evictStale(now)
		return true
	}
	b.tokens += now.Sub(b.lastSeen).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictStale drops buckets idle long enough to be fully refilled anyway.
func (l *TokenBucketLimiter) evictStale(now time.Time) {
	if len(l.buckets) < 10000 {
		return
	}
	idle := time.Duration(l.burst/l.rate) * time.Second
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > idle {
			delete(l.buckets, k)
		}
	}
}

// RateLimit applies the limiter to the given exact request paths, keyed by client IP + path.
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
			if !limiter.Allow(clientIP(r) + " " + r.URL.Path) {
				w.Header().Set("Retry-After", "60")
				httpx.Error(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP reads the peer address. RealIP has already resolved X-Forwarded-For
// into RemoteAddr and stripped the header, so RemoteAddr is authoritative here.
func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return host
}
