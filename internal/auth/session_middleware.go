package auth

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/users"
)

const csrfCookieName = "sso_csrf"

func ProtectedAuth(verifier AccessTokenVerifier, sessions SessionRepository, userRepo users.Repository, revocations TokenChecker) func(http.Handler) http.Handler {
	bearer := BearerAuth(verifier, revocations)
	return func(next http.Handler) http.Handler {
		bearerNext := bearer(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				bearerNext.ServeHTTP(w, r)
				return
			}
			cookie, err := r.Cookie("sso_session")
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "missing session")
				return
			}
			sess, err := sessions.FindByTokenHash(r.Context(), HashSessionToken(cookie.Value))
			if err != nil || sess.RevokedAt != nil || !sess.ExpiresAt.After(time.Now()) {
				httpx.Error(w, http.StatusUnauthorized, "invalid session")
				return
			}
			u, err := userRepo.FindByID(r.Context(), sess.UserID)
			if err != nil || u.Status != users.StatusActive {
				httpx.Error(w, http.StatusUnauthorized, "invalid session")
				return
			}
			if isUnsafeMethod(r.Method) && (!ValidCSRF(r) || !ValidRequestOrigin(r)) {
				httpx.Error(w, http.StatusForbidden, "invalid csrf token")
				return
			}
			claims := &Claims{UserID: u.ID.String(), Username: u.Username, Email: u.Email, Source: u.Source}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
		})
	}
}

func ValidRequestOrigin(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	scheme := "http"
	if httpx.IsHTTPS(r) {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

func isUnsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func ValidCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	h := r.Header.Get("X-CSRF-Token")
	return err == nil && c.Value != "" && len(c.Value) == len(h) && subtle.ConstantTimeCompare([]byte(c.Value), []byte(h)) == 1
}

func SetSessionCookies(w http.ResponseWriter, r *http.Request, result LoginResult) error {
	csrf, _, err := NewSessionToken()
	if err != nil {
		return err
	}
	secure := httpx.IsHTTPS(r)
	http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: result.SessionToken, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: result.SessionExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/", Secure: secure, SameSite: http.SameSiteLaxMode, Expires: result.SessionExpiresAt})
	return nil
}

func ClearSessionCookies(w http.ResponseWriter, r *http.Request) {
	secure := httpx.IsHTTPS(r)
	http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", MaxAge: -1, Secure: secure, SameSite: http.SameSiteLaxMode})
}

func BrowserLoginResult(result LoginResult) any {
	return struct {
		User             users.User `json:"user"`
		SessionExpiresAt time.Time  `json:"session_expires_at"`
		MFARequired      bool       `json:"mfa_required,omitempty"`
		MFAToken         string     `json:"mfa_token,omitempty"`
	}{result.User, result.SessionExpiresAt, result.MFARequired, result.MFAToken}
}
