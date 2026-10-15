package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func allow(t testing.TB, limiter RateLimiter, key string) bool {
	t.Helper()
	allowed, err := limiter.Allow(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return allowed
}

func TestTokenBucketLimiterBurstAndRefill(t *testing.T) {
	l := NewTokenBucketLimiter(60, 3)
	for i := 0; i < 3; i++ {
		if !allow(t, l, "k") {
			t.Fatalf("request %d within burst must pass", i+1)
		}
	}
	if allow(t, l, "k") {
		t.Fatal("request beyond burst must be rejected")
	}
	if !allow(t, l, "other") {
		t.Fatal("different key must have its own bucket")
	}
}

func TestTokenBucketLimiterBoundsUniqueKeys(t *testing.T) {
	l := newTokenBucketLimiter(60, 1, 128, time.Now)
	for i := 0; i < 100_000; i++ {
		if !allow(t, l, fmt.Sprintf("192.0.2.%d", i)) {
			t.Fatalf("новый ключ %d должен получить первый токен", i)
		}
	}
	stats := l.Stats()
	if stats.Buckets != 128 {
		t.Fatalf("число buckets = %d, want 128", stats.Buckets)
	}
	if stats.CapacityEvictions != 100_000-128 {
		t.Fatalf("вытеснений по ёмкости = %d, want %d", stats.CapacityEvictions, 100_000-128)
	}
}

func TestTokenBucketLimiterEvictsExpiredLRUEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newTokenBucketLimiter(60, 1, 3, func() time.Time { return now })
	allow(t, l, "first")
	allow(t, l, "second")
	now = now.Add(time.Second)
	allow(t, l, "third")
	stats := l.Stats()
	if stats.Buckets != 1 || stats.TTLEvictions != 2 {
		t.Fatalf("неверное TTL-вытеснение: %+v", stats)
	}
}

func TestTokenBucketLimiterEvictsLeastRecentlyUsedEntryAtCapacity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newTokenBucketLimiter(60, 2, 2, func() time.Time { return now })
	allow(t, l, "first")
	allow(t, l, "second")
	allow(t, l, "first")
	allow(t, l, "third")
	if _, ok := l.buckets["second"]; ok {
		t.Fatal("наименее недавно использованный ключ не вытеснен")
	}
	if _, ok := l.buckets["first"]; !ok {
		t.Fatal("недавно использованный ключ ошибочно вытеснен")
	}
}

type failingRateLimiter struct{}

func (failingRateLimiter) Allow(context.Context, string) (bool, error) {
	return false, errors.New("storage unavailable")
}

func TestRateLimitFailsClosedWhenSharedStorageIsUnavailable(t *testing.T) {
	h := RateLimit(failingRateLimiter{}, "/api/v1/auth/login")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatal("ответ fail-closed должен содержать Retry-After")
	}
}

func TestRateLimitMiddlewareOnlyLimitsConfiguredPaths(t *testing.T) {
	l := NewTokenBucketLimiter(60, 1)
	h := RateLimit(l, "/api/v1/auth/login")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	do := func(path string) int {
		req := httptest.NewRequest("POST", path, nil)
		req.RemoteAddr = "1.2.3.4:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("/api/v1/auth/login"); code != 200 {
		t.Fatalf("first request: want 200, got %d", code)
	}
	if code := do("/api/v1/auth/login"); code != 429 {
		t.Fatalf("second request: want 429, got %d", code)
	}
	if code := do("/health/live"); code != 200 {
		t.Fatalf("unlimited path: want 200, got %d", code)
	}
}

func BenchmarkTokenBucketLimiterUniqueKeys(b *testing.B) {
	l := NewTokenBucketLimiter(60, 1)
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = l.Allow(ctx, fmt.Sprintf("198.51.100.%d", i))
	}
}
