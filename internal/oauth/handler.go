package oauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// oauthError writes an RFC 6749 error response: {"error": ..., "error_description": ...}.
func oauthError(w http.ResponseWriter, status int, code, description string) {
	httpx.JSON(w, status, map[string]string{"error": code, "error_description": description})
}

// tokenError maps service errors to RFC 6749 token endpoint error codes.
func tokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidClient):
		w.Header().Set("WWW-Authenticate", `Basic realm="sso"`)
		oauthError(w, 401, "invalid_client", "client authentication failed")
	case errors.Is(err, ErrInvalidGrant):
		oauthError(w, 400, "invalid_grant", "grant is invalid, expired or revoked")
	case errors.Is(err, ErrInvalidScope):
		oauthError(w, 400, "invalid_scope", "requested scope is not allowed for this client")
	case err.Error() == "unsupported grant_type":
		oauthError(w, 400, "unsupported_grant_type", "grant_type is not supported")
	default:
		oauthError(w, 400, "invalid_request", err.Error())
	}
}

func sessionCookie(r *http.Request) string {
	c, _ := r.Cookie("sso_session")
	if c == nil {
		return ""
	}
	return c.Value
}

// clientCredentials extracts client_id/client_secret from the form or the Basic
// header (RFC 6749 §2.3.1: Basic credentials are form-urlencoded).
func clientCredentials(r *http.Request) (string, string) {
	clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	if id, sec, ok := r.BasicAuth(); ok {
		if v, err := url.QueryUnescape(id); err == nil {
			id = v
		}
		if v, err := url.QueryUnescape(sec); err == nil {
			sec = v
		}
		clientID, clientSecret = id, sec
	}
	return clientID, clientSecret
}

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler, require func(string, string) func(http.Handler) http.Handler) {
	r.Route("/api/v1/oauth/clients", func(r chi.Router) {
		r.Use(bearerAuth)
		r.With(require("oauth_clients", "read")).Get("/", func(w http.ResponseWriter, r *http.Request) {
			out, err := svc.ListClients(r.Context())
			if err != nil {
				httpx.Error(w, 500, "failed to list clients")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("oauth_clients", "create")).Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateClientInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			out, err := svc.CreateClient(r.Context(), req)
			if err != nil {
				httpx.Error(w, 500, "failed to create client")
				return
			}
			httpx.JSON(w, 201, out)
		})
		r.With(require("oauth_clients", "read")).Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			out, err := svc.GetClient(r.Context(), id)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "client not found")
					return
				}
				httpx.Error(w, 500, "failed to load client")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("oauth_clients", "update")).Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			var req UpdateClientInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			out, err := svc.UpdateClient(r.Context(), id, req)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "client not found")
					return
				}
				httpx.Error(w, 500, "failed to update client")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(require("oauth_clients", "delete")).Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid id")
				return
			}
			if err := svc.DeleteClient(r.Context(), id); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "client not found")
					return
				}
				httpx.Error(w, 500, "failed to delete client")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "deleted"})
		})
	})
	r.Get("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.Authorize(r.Context(), AuthorizeInput{ResponseType: r.URL.Query().Get("response_type"), ClientID: r.URL.Query().Get("client_id"), RedirectURI: r.URL.Query().Get("redirect_uri"), Scope: r.URL.Query().Get("scope"), State: r.URL.Query().Get("state"), CodeChallenge: r.URL.Query().Get("code_challenge"), CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"), Nonce: r.URL.Query().Get("nonce"), SessionToken: sessionCookie(r)})
		if err != nil {
			switch {
			case errors.Is(err, ErrLoginRequired):
				oauthError(w, 401, "login_required", "no active session, authenticate first")
			case errors.Is(err, ErrConsentRequired):
				oauthError(w, 403, "consent_required", "user consent is required for the requested scopes")
			case errors.Is(err, ErrInvalidScope):
				oauthError(w, 400, "invalid_scope", "requested scope is not allowed for this client")
			default:
				oauthError(w, 400, "invalid_request", err.Error())
			}
			return
		}
		http.Redirect(w, r, out.Redirect, http.StatusFound)
	})
	logout := func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		param := func(key string) string {
			if v := r.Form.Get(key); v != "" {
				return v
			}
			return r.URL.Query().Get(key)
		}
		redirect, err := svc.Logout(r.Context(), LogoutInput{IDTokenHint: param("id_token_hint"), PostLogoutRedirectURI: param("post_logout_redirect_uri"), State: param("state"), SessionToken: sessionCookie(r)})
		if err != nil {
			oauthError(w, 400, "invalid_request", err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
		httpx.JSON(w, 200, map[string]string{"status": "logged_out"})
	}
	r.Get("/oauth2/logout", logout)
	r.Post("/oauth2/logout", logout)
	r.Get("/oauth2/consent", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.GetConsentInfo(r.Context(), sessionCookie(r), r.URL.Query().Get("client_id"), r.URL.Query().Get("scope"))
		if err != nil {
			switch {
			case errors.Is(err, ErrLoginRequired):
				oauthError(w, 401, "login_required", "no active session")
			case errors.Is(err, ErrInvalidScope):
				oauthError(w, 400, "invalid_scope", "requested scope is not allowed for this client")
			default:
				oauthError(w, 400, "invalid_request", err.Error())
			}
			return
		}
		httpx.JSON(w, 200, out)
	})
	r.Post("/oauth2/consent", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID string `json:"client_id"`
			Scope    string `json:"scope"`
		}
		if err := httpx.Decode(r, &req); err != nil {
			oauthError(w, 400, "invalid_request", "invalid json body")
			return
		}
		if err := svc.GrantConsent(r.Context(), sessionCookie(r), req.ClientID, req.Scope); err != nil {
			switch {
			case errors.Is(err, ErrLoginRequired):
				oauthError(w, 401, "login_required", "no active session")
			case errors.Is(err, ErrInvalidScope):
				oauthError(w, 400, "invalid_scope", "requested scope is not allowed for this client")
			default:
				oauthError(w, 400, "invalid_request", err.Error())
			}
			return
		}
		httpx.JSON(w, 200, map[string]string{"status": "granted"})
	})
	r.Post("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpx.Error(w, 400, "invalid form")
			return
		}
		clientID, clientSecret := clientCredentials(r)
		out, err := svc.Token(r.Context(), TokenInput{GrantType: r.Form.Get("grant_type"), Code: r.Form.Get("code"), RedirectURI: r.Form.Get("redirect_uri"), ClientID: clientID, ClientSecret: clientSecret, CodeVerifier: r.Form.Get("code_verifier"), RefreshToken: r.Form.Get("refresh_token"), Scope: r.Form.Get("scope")})
		if err != nil {
			tokenError(w, err)
			return
		}
		httpx.JSON(w, 200, out)
	})
	r.Post("/oauth2/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			oauthError(w, 400, "invalid_request", "invalid form")
			return
		}
		clientID, clientSecret := clientCredentials(r)
		if err := svc.Revoke(r.Context(), RevokeInput{Token: r.Form.Get("token"), ClientID: clientID, ClientSecret: clientSecret}); err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="sso"`)
			oauthError(w, 401, "invalid_client", "client authentication failed")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	r.Post("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			oauthError(w, 400, "invalid_request", "invalid form")
			return
		}
		clientID, clientSecret := clientCredentials(r)
		out, err := svc.Introspect(r.Context(), IntrospectInput{Token: r.Form.Get("token"), ClientID: clientID, ClientSecret: clientSecret})
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="sso"`)
			oauthError(w, 401, "invalid_client", "client authentication failed")
			return
		}
		httpx.JSON(w, 200, out)
	})
}
