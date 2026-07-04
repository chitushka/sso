package users

import (
	"errors"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http"
	"strconv"
	"strings"
)

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(require("users", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			out, err := svc.List(r.Context(), limit, offset)
			if err != nil {
				httpx.Error(w, 500, "failed to list users")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("users", "create")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateUserInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			u, err := svc.Create(r.Context(), req, clientIP(r), r.UserAgent())
			if err != nil {
				if errors.Is(err, storage.ErrConflict) {
					httpx.Error(w, 409, "user already exists")
					return
				}
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 201, u)
		})
		r.With(require("users", "read")).Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			u, err := svc.Get(r.Context(), id)
			if err != nil {
				httpx.Error(w, 404, "user not found")
				return
			}
			httpx.JSON(w, 200, u)
		})
		r.With(require("users", "delete")).Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			if err := svc.Delete(r.Context(), id, clientIP(r), r.UserAgent()); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "user not found")
					return
				}
				httpx.Error(w, 500, "failed to delete user")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "deleted"})
		})
		r.With(require("users", "update")).Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			var req UpdateUserInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			u, err := svc.Update(r.Context(), id, req)
			if err != nil {
				httpx.Error(w, 500, "failed to update user")
				return
			}
			httpx.JSON(w, 200, u)
		})
	})
}
func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	return r.RemoteAddr
}
