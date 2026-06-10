package ldap

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler) {
	r.Route("/api/v1/ldap/providers", func(r chi.Router) {
		r.Use(bearerAuth)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			providers, err := svc.List(r.Context(), limit, offset)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list ldap providers")
				return
			}
			httpx.JSON(w, http.StatusOK, providers)
		})
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req ProviderInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			p, err := svc.Create(r.Context(), req, clientIP(r), r.UserAgent())
			writeProviderResult(w, p, err, http.StatusCreated)
		})
		r.Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, ok := parseUUIDParam(w, r)
			if !ok {
				return
			}
			p, err := svc.Get(r.Context(), id)
			writeProviderResult(w, p, err, http.StatusOK)
		})
		r.Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, ok := parseUUIDParam(w, r)
			if !ok {
				return
			}
			var req ProviderInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			p, err := svc.Update(r.Context(), id, req, clientIP(r), r.UserAgent())
			writeProviderResult(w, p, err, http.StatusOK)
		})
		r.Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, ok := parseUUIDParam(w, r)
			if !ok {
				return
			}
			if err := svc.Delete(r.Context(), id, clientIP(r), r.UserAgent()); err != nil {
				writeLDAPError(w, err)
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		})
		r.Post("/{id}/test", func(w http.ResponseWriter, r *http.Request) {
			id, ok := parseUUIDParam(w, r)
			if !ok {
				return
			}
			res, err := svc.Test(r.Context(), id)
			if err != nil {
				writeLDAPError(w, err)
				return
			}
			httpx.JSON(w, http.StatusOK, res)
		})
	})
}

func writeProviderResult(w http.ResponseWriter, p Provider, err error, status int) {
	if err != nil {
		writeLDAPError(w, err)
		return
	}
	httpx.JSON(w, status, p)
}

func writeLDAPError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "ldap provider not found")
		return
	}
	if errors.Is(err, storage.ErrConflict) {
		httpx.Error(w, http.StatusConflict, "ldap provider already exists")
		return
	}
	httpx.Error(w, http.StatusBadRequest, err.Error())
}

func parseUUIDParam(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, false
	}
	return id, true
}

func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	return r.RemoteAddr
}
