package middleware

import "net/http"

// BodyLimit caps request body size to guard against memory exhaustion from
// oversized JSON/form payloads. Reading beyond the limit fails the handler's
// decode and http.MaxBytesReader makes the server answer 413.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}
