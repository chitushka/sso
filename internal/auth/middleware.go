package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/chitushka/sso/internal/httpx"
)

type claimsKey struct{}

func BearerAuth(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				httpx.Error(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			claims, err := ParseToken(secret, strings.TrimPrefix(h, "Bearer "))
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
		})
	}
}
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsKey{}).(*Claims)
	return c
}
