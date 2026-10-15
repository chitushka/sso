package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeRateLimitEvictions(t *testing.T) {
	l := newTokenBucketLimiter(60, 1, 1, time.Now)
	allow(t, l, "first")
	allow(t, l, "second")
	m := NewMetrics().WithRateLimiter(l)
	w := httptest.NewRecorder()
	m.Expose(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		"sso_rate_limit_local_buckets 1",
		`sso_rate_limit_local_evictions_total{reason="capacity"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("метрика %q отсутствует в %q", want, body)
		}
	}
}
