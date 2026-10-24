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
			t.Fatal("пользователь сессии не добавлен в контекст")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	request := func(csrf, origin, fetchSite string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
		req.AddCookie(&http.Cookie{Name: "sso_session", Value: "opaque"})
		req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf"})
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			req.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Code
	}

	for name, test := range map[string]struct {
		csrf, origin, fetchSite string
		wantStatus              int
	}{
		"нет CSRF-заголовка":            {origin: "http://example.com", wantStatus: http.StatusForbidden},
		"неверный CSRF-токен":           {csrf: "wrong", origin: "http://example.com", wantStatus: http.StatusForbidden},
		"чужой Origin":                  {csrf: "csrf", origin: "https://evil.example", wantStatus: http.StatusForbidden},
		"cross-site Fetch Metadata":     {csrf: "csrf", origin: "http://example.com", fetchSite: "cross-site", wantStatus: http.StatusForbidden},
		"корректный same-origin запрос": {csrf: "csrf", origin: "http://example.com", fetchSite: "same-origin", wantStatus: http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			if status := request(test.csrf, test.origin, test.fetchSite); status != test.wantStatus {
				t.Fatalf("status=%d, ожидался %d", status, test.wantStatus)
			}
		})
	}
}
