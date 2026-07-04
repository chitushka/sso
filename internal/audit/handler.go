package audit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, reader Reader, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	r.Route("/api/v1/audit", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(require("audit", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			f := Filter{Action: r.URL.Query().Get("action")}
			if v := r.URL.Query().Get("actor"); v != "" {
				id, err := uuid.Parse(v)
				if err != nil {
					httpx.Error(w, 400, "invalid actor id")
					return
				}
				f.ActorUserID = &id
			}
			if v := r.URL.Query().Get("from"); v != "" {
				t, err := time.Parse(time.RFC3339, v)
				if err != nil {
					httpx.Error(w, 400, "invalid from, expected RFC3339")
					return
				}
				f.From = &t
			}
			if v := r.URL.Query().Get("to"); v != "" {
				t, err := time.Parse(time.RFC3339, v)
				if err != nil {
					httpx.Error(w, 400, "invalid to, expected RFC3339")
					return
				}
				f.To = &t
			}
			f.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
			if f.Limit <= 0 || f.Limit > 200 {
				f.Limit = 50
			}
			f.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
			if f.Offset < 0 {
				f.Offset = 0
			}
			out, err := reader.List(r.Context(), f)
			if err != nil {
				httpx.Error(w, 500, "failed to list audit events")
				return
			}
			httpx.JSON(w, 200, out)
		})
	})
}
