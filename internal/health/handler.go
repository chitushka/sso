package health

import (
	"net/http"

	"github.com/chitushka/sso/internal/dbmigrate"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func RegisterRoutes(r chi.Router, pool *pgxpool.Pool, version string) {
	r.Get("/health/live", func(w http.ResponseWriter, r *http.Request) { httpx.JSON(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			httpx.Error(w, 503, "database unavailable")
			return
		}
		if err := dbmigrate.CheckSchema(r.Context(), pool); err != nil {
			httpx.Error(w, 503, "database schema is not current")
			return
		}
		httpx.JSON(w, 200, map[string]string{"status": "ready"})
	})
	r.Get("/health/version", func(w http.ResponseWriter, r *http.Request) {
		httpx.JSON(w, 200, map[string]string{"version": version})
	})
}
