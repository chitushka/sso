package oidc

import (
	"net/http"
	"strings"

	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/users"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, svc *Service, userRepo users.Repository, bearerAuth func(http.Handler) http.Handler) {
	r.Get("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) { httpx.JSON(w, 200, svc.Discovery()) })
	r.Get("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.JWKS(r.Context())
		if err != nil {
			httpx.Error(w, 500, "failed to load jwks")
			return
		}
		httpx.JSON(w, 200, out)
	})
	r.With(bearerAuth).Get("/oauth2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		claims := auth.ClaimsFromContext(r.Context())
		id, err := uuid.Parse(claims.UserID)
		if err != nil {
			httpx.Error(w, 401, "invalid token")
			return
		}
		u, err := userRepo.FindByID(r.Context(), id)
		if err != nil {
			httpx.Error(w, 404, "user not found")
			return
		}
		out := map[string]any{"sub": u.ID.String()}
		// Claims are filtered by the token's scope; tokens without a scope claim
		// (issued by the local login endpoint) keep the pre-v0.6.5 full response.
		scope := " " + claims.Scope + " "
		full := claims.Scope == ""
		if full || strings.Contains(scope, " profile ") {
			out["preferred_username"] = u.Username
			out["source"] = u.Source
		}
		if full || strings.Contains(scope, " email ") {
			out["email"] = u.Email
		}
		httpx.JSON(w, 200, out)
	})
}
