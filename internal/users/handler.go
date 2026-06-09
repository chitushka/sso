package users

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type setPasswordRequest struct {
	Password string `json:"password"`
}

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler) {

	r.Post("/api/v1/bootstrap/admin", func(w http.ResponseWriter, r *http.Request) {
		count, err := svc.repo.Count(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, "failed to check bootstrap state")
			return
		}
		if count > 0 {
			httpx.Error(w, http.StatusConflict, "bootstrap is already completed")
			return
		}
		var req CreateUserInput
		if err := httpx.Decode(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid json body")
			return
		}
		req.Status = StatusActive
		u, err := svc.Create(r.Context(), req, r.RemoteAddr, r.UserAgent())
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.JSON(w, http.StatusCreated, u)
	})

	r.Route("/api/v1/users", func(r chi.Router) {
		r.Use(bearerAuth)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			users, err := svc.List(r.Context(), limit, offset)
			if err != nil {
				httpx.Error(w, 500, "failed to list users")
				return
			}
			httpx.JSON(w, 200, users)
		})
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateUserInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			u, err := svc.Create(r.Context(), req, r.RemoteAddr, r.UserAgent())
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
		r.Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid user id")
				return
			}
			u, err := svc.Get(r.Context(), id)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "user not found")
					return
				}
				httpx.Error(w, 500, "failed to get user")
				return
			}
			httpx.JSON(w, 200, u)
		})
		r.Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid user id")
				return
			}
			var req UpdateUserInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			u, err := svc.Update(r.Context(), id, req)
			if err != nil {
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, u)
		})
		r.Post("/{id}/password", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid user id")
				return
			}
			var req setPasswordRequest
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			if err := svc.SetPassword(r.Context(), id, req.Password); err != nil {
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "password_updated"})
		})
	})
}
