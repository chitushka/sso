package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
)

// Metrics collects lightweight in-process counters exposed at /metrics in
// Prometheus text format. Kept dependency-free on purpose; swap for the
// Prometheus client if richer instrumentation is needed.
type Metrics struct {
	requests    sync.Map // "METHOD path status" -> *int64
	inflight    int64
	totalMicros int64
	totalCount  int64
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&m.inflight, 1)
		defer atomic.AddInt64(&m.inflight, -1)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(sw, r)
		atomic.AddInt64(&m.totalMicros, time.Since(start).Microseconds())
		atomic.AddInt64(&m.totalCount, 1)
		key := r.Method + " " + routePattern(r) + " " + fmt.Sprint(sw.status)
		v, _ := m.requests.LoadOrStore(key, new(int64))
		atomic.AddInt64(v.(*int64), 1)
	})
}

// Expose writes the collected counters in Prometheus text exposition format.
func (m *Metrics) Expose(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	b.WriteString("# TYPE sso_http_requests_total counter\n")
	m.requests.Range(func(k, v any) bool {
		parts := strings.SplitN(k.(string), " ", 3)
		if len(parts) == 3 {
			fmt.Fprintf(&b, "sso_http_requests_total{method=%q,route=%q,status=%q} %d\n", parts[0], parts[1], parts[2], atomic.LoadInt64(v.(*int64)))
		}
		return true
	})
	fmt.Fprintf(&b, "# TYPE sso_http_inflight gauge\nsso_http_inflight %d\n", atomic.LoadInt64(&m.inflight))
	fmt.Fprintf(&b, "# TYPE sso_http_request_duration_seconds_sum counter\nsso_http_request_duration_seconds_sum %f\n", float64(atomic.LoadInt64(&m.totalMicros))/1e6)
	fmt.Fprintf(&b, "# TYPE sso_http_requests_processed_total counter\nsso_http_requests_processed_total %d\n", atomic.LoadInt64(&m.totalCount))
	_, _ = w.Write([]byte(b.String()))
}

// routePattern returns the matched chi route template (e.g. /api/v1/users/{id})
// to keep label cardinality bounded; falls back to a constant for unmatched paths.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "other"
}
