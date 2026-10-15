package middleware

import (
	"context"
	"net/http"
	"regexp"

	"github.com/google/uuid"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

const maxRequestIDLength = 64

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if len(id) == 0 || len(id) > maxRequestIDLength || !requestIDPattern.MatchString(id) {
			id = uuid.NewString()
		}
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}
