package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type cookieSessions struct{ session Session }

func (r cookieSessions) Create(context.Context, Session) (Session, error) { return Session{}, nil }
func (r cookieSessions) FindByTokenHash(context.Context, string) (Session, error) {
	return r.session, nil
}
func (r cookieSessions) RevokeByTokenHash(context.Context, string) error  { return nil }
func (r cookieSessions) RevokeAllByUser(context.Context, uuid.UUID) error { return nil }

func TestSetSessionCookiesDisablesCaching(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	w := httptest.NewRecorder()
	result := LoginResult{SessionToken: "opaque", SessionExpiresAt: time.Now().Add(time.Hour)}
	if err := SetSessionCookies(w, req, result); err != nil {
		t.Fatal(err)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q, want no-cache", got)
	}
}

func TestProtectedAuthCookieRequiresCSRFForWrites(t *testing.T) {
	userID := uuid.New()
	userRepo := &memUsers{u: users.User{ID: userID, Username: "admin", Status: users.StatusActive}}
	sessions := cookieSessions{session: Session{UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}}
	handler := ProtectedAuth(nil, sessions, userRepo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ClaimsFromContext(r.Context()).UserID != userID.String() {
			t.Fatal("session user was not placed in context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "opaque"})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF header: got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "opaque"})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	req.Header.Set("X-CSRF-Token", "csrf")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("valid CSRF token: got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: "opaque"})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
	req.Header.Set("X-CSRF-Token", "csrf")
	req.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site origin: got %d", w.Code)
	}
}
