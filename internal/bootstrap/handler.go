package bootstrap

import (
	"errors"
	"net/http"
	"strings"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
)

func RegisterRoutes(r chi.Router, svc *Service) {
	r.Route("/api/v1/bootstrap", func(r chi.Router) {
		r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
			status, err := svc.Status(r.Context())
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to check bootstrap state")
				return
			}
			httpx.JSON(w, http.StatusOK, status)
		})

		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateAdminInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}

			res, err := svc.CreateAdmin(r.Context(), req, clientIP(r), r.UserAgent())
			if err != nil {
				switch {
				case errors.Is(err, ErrAlreadyInitialized):
					httpx.Error(w, http.StatusConflict, "system already initialized")
				case errors.Is(err, ErrInvalidInput):
					httpx.Error(w, http.StatusBadRequest, err.Error())
				default:
					httpx.Error(w, http.StatusInternalServerError, "bootstrap failed")
				}
				return
			}
			httpx.JSON(w, http.StatusCreated, res)
		})
	})
}

func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	return r.RemoteAddr
}
