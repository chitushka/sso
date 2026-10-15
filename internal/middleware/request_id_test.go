package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestRequestID(t *testing.T) {
	tests := []struct {
		name     string
		provided string
		preserve bool
	}{
		{name: "допустимое значение", provided: "edge-01:request_42", preserve: true},
		{name: "пустое значение"},
		{name: "слишком длинное значение", provided: strings.Repeat("a", maxRequestIDLength+1)},
		{name: "пробел", provided: "unsafe value"},
		{name: "не-ASCII", provided: "запрос-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var contextID string
			h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contextID = RequestIDFromContext(r.Context())
				if headerID := r.Header.Get("X-Request-ID"); headerID != contextID {
					t.Errorf("request ID в заголовке = %q, в контексте = %q", headerID, contextID)
				}
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.provided != "" {
				r.Header.Set("X-Request-ID", tt.provided)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			got := w.Header().Get("X-Request-ID")
			if tt.preserve {
				if got != tt.provided {
					t.Fatalf("X-Request-ID = %q, ожидалось %q", got, tt.provided)
				}
			} else if _, err := uuid.Parse(got); err != nil {
				t.Fatalf("сгенерирован некорректный UUID %q: %v", got, err)
			}
			if contextID != got {
				t.Fatalf("request ID в контексте = %q, в ответе = %q", contextID, got)
			}
		})
	}
}
