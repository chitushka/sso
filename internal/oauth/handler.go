package oauth

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type createClientResponse struct {
	Client       Client `json:"client"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func RegisterRoutes(r chi.Router, svc *Service, bearerAuth func(http.Handler) http.Handler) {
	r.Route("/api/v1/oauth/clients", func(r chi.Router) {
		r.Use(bearerAuth)
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			items, err := svc.ListClients(r.Context(), limit, offset)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, "failed to list oauth clients")
				return
			}
			httpx.JSON(w, http.StatusOK, items)
		})
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var req CreateClientInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			client, secret, err := svc.CreateClient(r.Context(), req, clientIP(r), r.UserAgent())
			if err != nil {
				if errors.Is(err, storage.ErrConflict) {
					httpx.Error(w, http.StatusConflict, "oauth client already exists")
					return
				}
				httpx.Error(w, http.StatusBadRequest, err.Error())
				return
			}
			httpx.JSON(w, http.StatusCreated, createClientResponse{Client: client, ClientSecret: secret})
		})
		r.Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid id")
				return
			}
			client, err := svc.GetClient(r.Context(), id)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "oauth client not found")
					return
				}
				httpx.Error(w, http.StatusInternalServerError, "failed to load oauth client")
				return
			}
			httpx.JSON(w, http.StatusOK, client)
		})
		r.Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid id")
				return
			}
			var req UpdateClientInput
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid json body")
				return
			}
			client, err := svc.UpdateClient(r.Context(), id, req)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "oauth client not found")
					return
				}
				httpx.Error(w, http.StatusBadRequest, err.Error())
				return
			}
			httpx.JSON(w, http.StatusOK, client)
		})
		r.Delete("/{id}", func(w http.ResponseWriter, r *http.Request) {
			id, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid id")
				return
			}
			if err := svc.DeleteClient(r.Context(), id); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, http.StatusNotFound, "oauth client not found")
					return
				}
				httpx.Error(w, http.StatusInternalServerError, "failed to delete oauth client")
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
		})
	})

	r.Get("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("sso_session")
		sessionToken := ""
		if cookie != nil {
			sessionToken = cookie.Value
		}
		res, err := svc.Authorize(r.Context(), AuthorizeInput{
			ResponseType:        r.URL.Query().Get("response_type"),
			ClientID:            r.URL.Query().Get("client_id"),
			RedirectURI:         r.URL.Query().Get("redirect_uri"),
			Scope:               r.URL.Query().Get("scope"),
			State:               r.URL.Query().Get("state"),
			CodeChallenge:       r.URL.Query().Get("code_challenge"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
			SessionToken:        sessionToken,
			IP:                  clientIP(r),
			UserAgent:           r.UserAgent(),
		})
		if err != nil {
			handleAuthorizeError(w, err)
			return
		}
		redirectURL, err := url.Parse(res.RedirectURI)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid redirect_uri")
			return
		}
		q := redirectURL.Query()
		q.Set("code", res.Code)
		if res.State != "" {
			q.Set("state", res.State)
		}
		redirectURL.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	})

	r.Post("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid form body")
			return
		}
		clientID, clientSecret := parseClientCredentials(r)
		res, err := svc.ExchangeCode(r.Context(), TokenInput{
			GrantType:    r.Form.Get("grant_type"),
			Code:         r.Form.Get("code"),
			RedirectURI:  r.Form.Get("redirect_uri"),
			ClientID:     firstNonEmpty(r.Form.Get("client_id"), clientID),
			ClientSecret: firstNonEmpty(r.Form.Get("client_secret"), clientSecret),
			CodeVerifier: r.Form.Get("code_verifier"),
			IP:           clientIP(r),
			UserAgent:    r.UserAgent(),
		})
		if err != nil {
			handleTokenError(w, err)
			return
		}
		httpx.JSON(w, http.StatusOK, res)
	})
}

func handleAuthorizeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrLoginRequired):
		httpx.Error(w, http.StatusUnauthorized, "login required")
	case errors.Is(err, ErrInvalidClient), errors.Is(err, ErrInvalidRedirectURI), errors.Is(err, ErrUnsupportedResponse), errors.Is(err, ErrInvalidScope), errors.Is(err, ErrInvalidPKCE):
		httpx.Error(w, http.StatusBadRequest, err.Error())
	default:
		httpx.Error(w, http.StatusInternalServerError, "authorization failed")
	}
}

func handleTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidClient):
		httpx.Error(w, http.StatusUnauthorized, "invalid client")
	case errors.Is(err, ErrInvalidCode), errors.Is(err, ErrUnsupportedGrant), errors.Is(err, ErrInvalidPKCE):
		httpx.Error(w, http.StatusBadRequest, err.Error())
	default:
		httpx.Error(w, http.StatusInternalServerError, "token exchange failed")
	}
}

func parseClientCredentials(r *http.Request) (string, string) {
	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		return clientID, clientSecret
	}
	return "", ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	return r.RemoteAddr
}
