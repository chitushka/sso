package ldap

import (
	"errors"
	"net/http"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	r.Route("/api/v1/ldap/providers", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(require("ldap", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.List(r.Context())
			if err != nil {
				httpx.Error(w, 500, "failed to list providers")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("ldap", "create")).Post("/", func(w http.ResponseWriter, r *http.Request) {
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
		r.With(require("ldap", "update")).Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			var p Provider
			if err := httpx.Decode(r, &p); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			p.ID = id
			out, err := svc.Update(r.Context(), p)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "provider not found")
					return
				}
				httpx.Error(w, 500, "failed to update provider")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("ldap", "delete")).Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			if err := svc.Delete(r.Context(), id); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "provider not found")
					return
				}
				httpx.Error(w, 500, "failed to delete provider")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "deleted"})
		})
		r.With(require("ldap", "read")).Get("/{id}/group-mappings", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			out, err := svc.ListGroupMappings(r.Context(), id)
			if err != nil {
				httpx.Error(w, 500, "failed to list group mappings")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("ldap", "update")).Post("/{id}/group-mappings", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			var m GroupMapping
			if err := httpx.Decode(r, &m); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			m.ProviderID = id
			out, err := svc.CreateGroupMapping(r.Context(), m)
			if err != nil {
				if errors.Is(err, storage.ErrConflict) {
					httpx.Error(w, 409, "mapping already exists")
					return
				}
				httpx.Error(w, 500, "failed to create mapping")
				return
			}
			httpx.JSON(w, 201, out)
		})
		r.With(require("ldap", "update")).Delete("/{id}/group-mappings/{mappingID}", func(w http.ResponseWriter, r *http.Request) {
			mappingID, err := uuid.Parse(chi.URLParam(r, "mappingID"))
			if err != nil {
				httpx.Error(w, 400, "invalid mapping id")
				return
			}
			if err := svc.DeleteGroupMapping(r.Context(), mappingID); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "mapping not found")
					return
				}
				httpx.Error(w, 500, "failed to delete mapping")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "deleted"})
		})
		r.With(require("ldap", "test")).Post("/test", func(w http.ResponseWriter, r *http.Request) {
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
