package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenBucketLimiterBurstAndRefill(t *testing.T) {
	l := NewTokenBucketLimiter(60, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("request %d within burst must pass", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("request beyond burst must be rejected")
	}
	if !l.Allow("other") {
		t.Fatal("different key must have its own bucket")
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
