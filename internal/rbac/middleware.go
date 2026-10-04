package rbac

import (
	"net"
	"net/http"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/google/uuid"
)

func RequirePermission(repo Repository, resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.ClaimsFromContext(r.Context())
			if claims == nil || claims.UserID == "" {
				httpx.Error(w, http.StatusUnauthorized, "missing auth claims")
				return
			}
			userID, err := uuid.Parse(claims.UserID)
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "invalid user id")
				return
			}
			ok, err := repo.HasPermission(r.Context(), userID, resource, action)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "permission check failed")
				return
			}
			if !ok {
				httpx.Error(w, http.StatusForbidden, "permission denied")
				return
			}
			ip := r.RemoteAddr
			if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
				ip = host
			}
			ctx := audit.WithRequestContext(r.Context(), userID, ip, r.UserAgent())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
