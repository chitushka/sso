package auth

import (
	"errors"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http"
	"strings"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func RegisterRoutes(r chi.Router, svc *Service, userRepo users.Repository, jwtSecret []byte) {
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			var req loginRequest
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			res, err := svc.Login(r.Context(), LoginInput{Username: req.Username, Password: req.Password, IP: clientIP(r), UserAgent: r.UserAgent()})
			if err != nil {
				if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrUserBlocked) {
					httpx.Error(w, 401, "invalid credentials")
					return
				}
				httpx.Error(w, 500, "login failed")
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: res.SessionToken, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: res.SessionExpiresAt})
			httpx.JSON(w, 200, res)
		})
		r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
			c, _ := r.Cookie("sso_session")
			if c != nil {
				_ = svc.Logout(r.Context(), c.Value)
			}
			http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
			httpx.JSON(w, 200, map[string]string{"status": "logged_out"})
		})
		r.With(BearerAuth(jwtSecret)).Get("/me", func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			id, err := uuid.Parse(claims.UserID)
			if err != nil {
				httpx.Error(w, 401, "invalid token")
				return
			}
			u, err := userRepo.FindByID(r.Context(), id)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "user not found")
					return
				}
				httpx.Error(w, 500, "failed to load user")
				return
			}
			httpx.JSON(w, 200, u)
		})
	})
}
func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		return strings.TrimSpace(strings.Split(x, ",")[0])
	}
	return r.RemoteAddr
}
