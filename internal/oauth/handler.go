package oauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
)

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
	})
	r.Get("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sso_session")
		token := ""
		if c != nil {
			token = c.Value
		}
		out, err := svc.Authorize(r.Context(), AuthorizeInput{ResponseType: r.URL.Query().Get("response_type"), ClientID: r.URL.Query().Get("client_id"), RedirectURI: r.URL.Query().Get("redirect_uri"), Scope: r.URL.Query().Get("scope"), State: r.URL.Query().Get("state"), CodeChallenge: r.URL.Query().Get("code_challenge"), CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"), Nonce: r.URL.Query().Get("nonce"), SessionToken: token})
		if err != nil {
			httpx.Error(w, 400, err.Error())
			return
		}
		http.Redirect(w, r, out.Redirect, http.StatusFound)
	})
	r.Post("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			httpx.Error(w, 400, "invalid form")
			return
		}
		clientID, clientSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")
		if id, sec, ok := r.BasicAuth(); ok {
			// RFC 6749 §2.3.1: credentials in the Basic header are form-urlencoded.
			if v, err := url.QueryUnescape(id); err == nil {
				id = v
			}
			if v, err := url.QueryUnescape(sec); err == nil {
				sec = v
			}
			clientID, clientSecret = id, sec
		}
		out, err := svc.Token(r.Context(), TokenInput{GrantType: r.Form.Get("grant_type"), Code: r.Form.Get("code"), RedirectURI: r.Form.Get("redirect_uri"), ClientID: clientID, ClientSecret: clientSecret, CodeVerifier: r.Form.Get("code_verifier")})
		if err != nil {
			if errors.Is(err, ErrInvalidClient) {
				w.Header().Set("WWW-Authenticate", `Basic realm="sso"`)
				httpx.Error(w, 401, "invalid_client")
				return
			}
			httpx.Error(w, 400, err.Error())
			return
		}
		httpx.JSON(w, 200, out)
	})
}
