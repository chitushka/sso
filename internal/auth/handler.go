package auth

import (
	"errors"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net"
	"net/http"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func RegisterRoutes(r chi.Router, svc *Service, userRepo users.Repository, sessions SessionBrowser, jwtSecret []byte) {
	r.Route("/api/v1/auth", func(r chi.Router) {
		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			var req loginRequest
			if err := httpx.Decode(r, &req); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			res, err := svc.Login(r.Context(), LoginInput{Username: req.Username, Password: req.Password, IP: clientIP(r), UserAgent: r.UserAgent()})
			if err != nil {
				if errors.Is(err, ErrLoginLocked) {
					httpx.Error(w, 429, "too many failed attempts, try again later")
					return
				}
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
		r.With(BearerAuth(jwtSecret)).Get("/sessions", func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			userID, err := uuid.Parse(claims.UserID)
			if err != nil {
				httpx.Error(w, 401, "invalid token")
				return
			}
			out, err := sessions.ListByUser(r.Context(), userID)
			if err != nil {
				httpx.Error(w, 500, "failed to list sessions")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(BearerAuth(jwtSecret)).Delete("/sessions/{id}", func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			userID, err := uuid.Parse(claims.UserID)
			if err != nil {
				httpx.Error(w, 401, "invalid token")
				return
			}
			sessionID, err := uuid.Parse(chi.URLParam(r, "id"))
			if err != nil {
				httpx.Error(w, 400, "invalid session id")
				return
			}
			if err := sessions.RevokeByID(r.Context(), userID, sessionID); err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					httpx.Error(w, 404, "session not found")
					return
				}
				httpx.Error(w, 500, "failed to revoke session")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "revoked"})
		})
		r.With(BearerAuth(jwtSecret)).Delete("/sessions", func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			userID, err := uuid.Parse(claims.UserID)
			if err != nil {
				httpx.Error(w, 401, "invalid token")
				return
			}
			if err := sessions.RevokeAllByUser(r.Context(), userID); err != nil {
				httpx.Error(w, 500, "failed to revoke sessions")
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
			httpx.JSON(w, 200, map[string]string{"status": "all_revoked"})
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

// clientIP returns the peer address. RealIP middleware has already resolved any
// trusted X-Forwarded-For into RemoteAddr and stripped the header, so trusting
// the header here would only reopen the per-IP lockout/rate-limit bypass.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
