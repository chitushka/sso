package broker

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	// Public: which sign-in buttons the login page shows.
	r.Get("/api/v1/broker/providers", func(w http.ResponseWriter, req *http.Request) {
		out, err := svc.PublicProviders(req.Context())
		if err != nil {
			httpx.Error(w, 500, "failed to list providers")
			return
		}
		httpx.JSON(w, 200, out)
	})

	r.Get("/oauth2/broker/{code}/login", func(w http.ResponseWriter, req *http.Request) {
		cont := req.URL.Query().Get("continue")
		if !safeContinue(cont) {
			cont = "/" // only same-origin continue targets
		}
		redirect, err := svc.Start(req.Context(), chi.URLParam(req, "code"), cont)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, ErrProviderDisabled) {
				httpx.Error(w, 404, "unknown identity provider")
				return
			}
			httpx.Error(w, 500, "failed to start external login")
			return
		}
		http.Redirect(w, req, redirect, http.StatusFound)
	})

	r.Get("/oauth2/broker/{code}/callback", func(w http.ResponseWriter, req *http.Request) {
		if e := req.URL.Query().Get("error"); e != "" {
			http.Redirect(w, req, "/login?broker_error="+e, http.StatusFound)
			return
		}
		res, cont, err := svc.Callback(req.Context(), chi.URLParam(req, "code"), req.URL.Query().Get("state"), req.URL.Query().Get("code"), auth.LoginInput{IP: clientIP(req), UserAgent: req.UserAgent()})
		if err != nil {
			http.Redirect(w, req, "/login?broker_error=failed", http.StatusFound)
			return
		}
		if err := auth.SetSessionCookies(w, req, res); err != nil {
			http.Redirect(w, req, "/login?broker_error=failed", http.StatusFound)
			return
		}
		if !safeContinue(cont) {
			cont = "/"
		}
		http.Redirect(w, req, cont, http.StatusFound)
	})

	r.Route("/api/v1/identity-providers", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(require("identity_providers", "read")).Get("/", func(w http.ResponseWriter, req *http.Request) {
			out, err := svc.List(req.Context())
			if err != nil {
				httpx.Error(w, 500, "failed to list identity providers")
				return
			}
			for i := range out {
				out[i].ClientSecret = "" // never expose secrets
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("identity_providers", "create")).Post("/", func(w http.ResponseWriter, req *http.Request) {
			var p Provider
			if err := httpx.Decode(req, &p); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			out, err := svc.Create(req.Context(), p)
			if err != nil {
				if errors.Is(err, storage.ErrConflict) {
					httpx.Error(w, 409, "provider already exists")
					return
				}
				httpx.Error(w, 400, err.Error())
				return
			}
			out.ClientSecret = ""
			httpx.JSON(w, 201, out)
		})
		r.With(require("identity_providers", "update")).Put("/{id}", func(w http.ResponseWriter, req *http.Request) {
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			var p Provider
			if err := httpx.Decode(req, &p); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			p.ID = id
			out, err := svc.Update(req.Context(), p)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "provider not found")
					return
				}

				httpx.Error(w, 400, err.Error())
				return
			}
			out.ClientSecret = ""
			httpx.JSON(w, 200, out)
		})
		r.With(require("identity_providers", "delete")).Delete("/{id}", func(w http.ResponseWriter, req *http.Request) {
			id, err := uuid.Parse(chi.URLParam(req, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			if err := svc.Delete(req.Context(), id); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "provider not found")
					return
				}
				httpx.Error(w, 500, "failed to delete provider")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "deleted"})
		})
	})
}

func safeContinue(target string) bool {
	return strings.HasPrefix(target, "/") &&
		!strings.HasPrefix(target, "//") &&
		!strings.HasPrefix(target, `/\`) &&
		!strings.ContainsAny(target, "\r\n")
}

// clientIP returns the peer address; RealIP has already folded any trusted
// X-Forwarded-For into RemoteAddr and removed the header.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
