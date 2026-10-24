package ldap

import (
	"errors"
	"net/http"
	"time"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// providerResponse намеренно не содержит BindPassword: транспортный слой не
// должен возвращать расшифрованный секрет ни при каких правах вызывающего.
type providerResponse struct {
	ID                   uuid.UUID `json:"id"`
	Name                 string    `json:"name"`
	Host                 string    `json:"host"`
	Port                 int       `json:"port"`
	UseTLS               bool      `json:"use_tls"`
	StartTLS             bool      `json:"start_tls"`
	BindDN               string    `json:"bind_dn"`
	BaseDN               string    `json:"base_dn"`
	UserFilter           string    `json:"user_filter"`
	UsernameAttribute    string    `json:"username_attribute"`
	EmailAttribute       string    `json:"email_attribute"`
	DisplayNameAttribute string    `json:"display_name_attribute"`
	GroupAttribute       string    `json:"group_attribute"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func newProviderResponse(p Provider) providerResponse {
	return providerResponse{
		ID:                   p.ID,
		Name:                 p.Name,
		Host:                 p.Host,
		Port:                 p.Port,
		UseTLS:               p.UseTLS,
		StartTLS:             p.StartTLS,
		BindDN:               p.BindDN,
		BaseDN:               p.BaseDN,
		UserFilter:           p.UserFilter,
		UsernameAttribute:    p.UsernameAttribute,
		EmailAttribute:       p.EmailAttribute,
		DisplayNameAttribute: p.DisplayNameAttribute,
		GroupAttribute:       p.GroupAttribute,
		Enabled:              p.Enabled,
		CreatedAt:            p.CreatedAt,
		UpdatedAt:            p.UpdatedAt,
	}
}

func newProviderResponses(providers []Provider) []providerResponse {
	out := make([]providerResponse, len(providers))
	for i, provider := range providers {
		out[i] = newProviderResponse(provider)
	}
	return out
}
func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	r.Route("/api/v1/ldap/providers", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(require("ldap", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.List(r.Context())
			if err != nil {
				httpx.Error(w, 500, "failed to list providers")
				return
			}
			httpx.JSON(w, 200, newProviderResponses(out))
		})
		r.With(require("ldap", "create")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			var p Provider
			if err := httpx.Decode(r, &p); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			out, err := svc.Create(r.Context(), p)
			if err != nil {
				if errors.Is(err, ErrTLSRequired) || errors.Is(err, ErrConflictingTLSModes) {
					httpx.Error(w, 400, err.Error())
					return
				}
				httpx.Error(w, 500, "failed to create provider")
				return
			}
			httpx.JSON(w, 201, newProviderResponse(out))
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
				if errors.Is(err, ErrTLSRequired) || errors.Is(err, ErrConflictingTLSModes) {
					httpx.Error(w, 400, err.Error())
					return
				}
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "provider not found")
					return
				}
				httpx.Error(w, 500, "failed to update provider")
				return
			}
			httpx.JSON(w, 200, newProviderResponse(out))
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
