package broker

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const brokerStateCookieName = "sso_broker_state"

func setBrokerStateCookie(w http.ResponseWriter, req *http.Request, state string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     brokerStateCookieName,
		Value:    state,
		Path:     "/oauth2/broker/",
		HttpOnly: true,
		Secure:   httpx.IsHTTPS(req),
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func clearBrokerStateCookie(w http.ResponseWriter, req *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     brokerStateCookieName,
		Value:    "",
		Path:     "/oauth2/broker/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   httpx.IsHTTPS(req),
		SameSite: http.SameSiteLaxMode,
	})
}

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	// Публичный список определяет кнопки внешнего входа на странице авторизации.
	r.Get("/api/v1/broker/providers", func(w http.ResponseWriter, req *http.Request) {
		out, err := svc.PublicProviders(req.Context())
		if err != nil {
			httpx.Error(w, 500, "failed to list providers")
			return
		}
		httpx.JSON(w, 200, out)
	})

	r.Get("/oauth2/broker/{code}/login", func(w http.ResponseWriter, req *http.Request) {
		httpx.NoStore(w)
		cont := req.URL.Query().Get("continue")
		if !safeContinue(cont) {
			cont = "/" // Разрешены только same-origin адреса продолжения.
		}
		result, err := svc.Start(req.Context(), chi.URLParam(req, "code"), cont)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || errors.Is(err, ErrProviderDisabled) {
				httpx.Error(w, 404, "unknown identity provider")
				return
			}
			httpx.Error(w, 500, "failed to start external login")
			return
		}
		setBrokerStateCookie(w, req, result.State, result.ExpiresAt)
		http.Redirect(w, req, result.Redirect, http.StatusFound)
	})

	r.Get("/oauth2/broker/{code}/callback", func(w http.ResponseWriter, req *http.Request) {
		httpx.NoStore(w)
		cookie, _ := req.Cookie(brokerStateCookieName)
		browserState := ""
		if cookie != nil {
			browserState = cookie.Value
		}
		clearBrokerStateCookie(w, req)
		if e := req.URL.Query().Get("error"); e != "" {
			http.Redirect(w, req, "/login?broker_error="+url.QueryEscape(e), http.StatusFound)
			return
		}
		res, cont, err := svc.Callback(req.Context(), chi.URLParam(req, "code"), req.URL.Query().Get("state"), browserState, req.URL.Query().Get("code"), auth.LoginInput{IP: httpx.ClientIP(req), UserAgent: req.UserAgent()})
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
				out[i].ClientSecret = "" // Секреты никогда не возвращаются клиенту.
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
