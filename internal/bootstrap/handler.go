package bootstrap

import (
	"errors"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strings"
)

func RegisterRoutes(r chi.Router, svc *Service) {
	r.Route("/api/v1/bootstrap", func(r chi.Router) {
		r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
			st, err := svc.Status(r.Context())
			if err != nil {
				httpx.Error(w, 500, "failed to check bootstrap state")
				return
			}
			httpx.JSON(w, 200, st)
		})
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateAdminInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			u, err := svc.CreateAdmin(r.Context(), req, clientIP(r), r.UserAgent())
			if err != nil {
				if errors.Is(err, ErrAlreadyInitialized) {
					httpx.Error(w, 409, "system already initialized")
					return
				}
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 201, u)
		})
	})
}
func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	return r.RemoteAddr
}
