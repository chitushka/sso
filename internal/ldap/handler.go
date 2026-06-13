package ldap

import (
	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
	"net/http"
)

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler) {
	r.Route("/api/v1/ldap/providers", func(r chi.Router) {
		r.Use(bearerAuth)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.List(r.Context())
			if err != nil {
				httpx.Error(w, 500, "failed to list providers")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var p Provider
			if err := httpx.Decode(r, &p); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			out, err := svc.Create(r.Context(), p)
			if err != nil {
				httpx.Error(w, 500, "failed to create provider")
				return
			}
			httpx.JSON(w, 201, out)
		})
		r.Post("/test", func(w http.ResponseWriter, r *http.Request) {
			var p Provider
			if err := httpx.Decode(r, &p); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			if err := svc.Test(r.Context(), p); err != nil {
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "ok"})
		})
	})
}
