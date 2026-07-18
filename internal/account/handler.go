package account

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func RegisterRoutes(r chi.Router, svc *Service, authSvc *auth.Service, bearerAuth func(http.Handler) http.Handler) {
	r.Route("/api/v1/auth/password", func(r chi.Router) {
		r.Post("/forgot", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Login string `json:"login"`
			}
			if err := httpx.Decode(req, &body); err != nil || strings.TrimSpace(body.Login) == "" {
				httpx.Error(w, 400, "login is required")
				return
			}
			svc.ForgotPassword(req.Context(), body.Login, clientIP(req), req.UserAgent())
			// Always 200: whether the account exists must not be observable.
			httpx.JSON(w, 200, map[string]string{"status": "ok"})
		})
		r.With(bearerAuth).Post("/change", func(w http.ResponseWriter, req *http.Request) {
			userID, ok := currentUser(w, req)
			if !ok {
				return
			}
			var body struct {
				OldPassword string `json:"old_password"`
				NewPassword string `json:"new_password"`
			}
			if err := httpx.Decode(req, &body); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			if err := svc.ChangePassword(req.Context(), userID, body.OldPassword, body.NewPassword); err != nil {
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "password_changed"})
		})
		r.Post("/reset", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Token    string `json:"token"`
				Password string `json:"password"`
			}
			if err := httpx.Decode(req, &body); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			if err := svc.ResetPassword(req.Context(), body.Token, body.Password, clientIP(req), req.UserAgent()); err != nil {
				if errors.Is(err, ErrInvalidToken) {
					httpx.Error(w, 400, "invalid or expired token")
					return
				}
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "password_reset"})
		})
	})

	r.Route("/api/v1/auth/email", func(r chi.Router) {
		r.With(bearerAuth).Post("/request", func(w http.ResponseWriter, req *http.Request) {
			userID, ok := currentUser(w, req)
			if !ok {
				return
			}
			if err := svc.RequestEmailVerification(req.Context(), userID); err != nil {
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "sent"})
		})
		r.Post("/verify", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				Token string `json:"token"`
			}
			if err := httpx.Decode(req, &body); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			if err := svc.VerifyEmail(req.Context(), body.Token); err != nil {
				httpx.Error(w, 400, "invalid or expired token")
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "email_verified"})
		})
	})

	r.Route("/api/v1/auth/mfa", func(r chi.Router) {
		r.With(bearerAuth).Post("/enroll", func(w http.ResponseWriter, req *http.Request) {
			userID, ok := currentUser(w, req)
			if !ok {
				return
			}
			out, err := svc.MFAEnroll(req.Context(), userID)
			if err != nil {
				if errors.Is(err, ErrMFAState) {
					httpx.Error(w, 409, "mfa already enabled")
					return
				}
				httpx.Error(w, 500, "failed to enroll")
				return
			}
			httpx.JSON(w, 200, out)
		})
		r.With(bearerAuth).Post("/activate", func(w http.ResponseWriter, req *http.Request) {
			userID, ok := currentUser(w, req)
			if !ok {
				return
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := httpx.Decode(req, &body); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			codes, err := svc.MFAActivate(req.Context(), userID, body.Code)
			if err != nil {
				if errors.Is(err, ErrInvalidCode) {
					httpx.Error(w, 400, "invalid code")
					return
				}
				if errors.Is(err, ErrMFAState) {
					httpx.Error(w, 409, "enroll first")
					return
				}
				httpx.Error(w, 500, "failed to activate")
				return
			}
			httpx.JSON(w, 200, map[string]any{"status": "mfa_enabled", "recovery_codes": codes})
		})
		r.With(bearerAuth).Post("/disable", func(w http.ResponseWriter, req *http.Request) {
			userID, ok := currentUser(w, req)
			if !ok {
				return
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := httpx.Decode(req, &body); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			if err := svc.MFADisable(req.Context(), userID, body.Code); err != nil {
				if errors.Is(err, ErrInvalidCode) {
					httpx.Error(w, 400, "invalid code")
					return
				}
				httpx.Error(w, 400, err.Error())
				return
			}
			httpx.JSON(w, 200, map[string]string{"status": "mfa_disabled"})
		})
		r.Post("/verify", func(w http.ResponseWriter, req *http.Request) {
			var body struct {
				MFAToken string `json:"mfa_token"`
				Code     string `json:"code"`
			}
			if err := httpx.Decode(req, &body); err != nil {
				httpx.Error(w, 400, "invalid json body")
				return
			}
			res, err := authSvc.CompleteMFALogin(req.Context(), body.MFAToken, body.Code, auth.LoginInput{IP: clientIP(req), UserAgent: req.UserAgent()})
			if err != nil {
				switch {
				case errors.Is(err, auth.ErrLoginLocked):
					httpx.Error(w, 429, "too many failed attempts, try again later")
				case errors.Is(err, auth.ErrInvalidMFACode):
					httpx.Error(w, 401, "invalid code")
				default:
					httpx.Error(w, 401, "invalid mfa token")
				}
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: res.SessionToken, Path: "/", HttpOnly: true, Secure: req.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: res.SessionExpiresAt})
			httpx.JSON(w, 200, res)
		})
	})
}

func currentUser(w http.ResponseWriter, req *http.Request) (uuid.UUID, bool) {
	claims := auth.ClaimsFromContext(req.Context())
	if claims == nil {
		httpx.Error(w, 401, "unauthorized")
		return uuid.Nil, false
	}
	id, err := uuid.Parse(claims.UserID)
	if err != nil {
		httpx.Error(w, 401, "invalid token")
		return uuid.Nil, false
	}
	return id, true
}

// clientIP returns the peer address; RealIP has already folded any trusted
// X-Forwarded-For into RemoteAddr and removed the header.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
