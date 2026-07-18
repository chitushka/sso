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

type stubChecker struct {
	active bool
	before *time.Time
}

func (s stubChecker) AccessState(_ context.Context, _ uuid.UUID) (bool, *time.Time, error) {
	return s.active, s.before, nil
}

func serve(mw func(http.Handler) http.Handler, token string) int {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	return rec.Code
}

func TestBearerAuthHonoursTokenRevocation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	issuer := NewJWTIssuer(secret, 15*time.Minute)
	u := users.User{ID: uuid.New(), Username: "alice", Source: users.SourceLocal}
	token, _, err := issuer.IssueOAuthAccessToken(u, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// Active account, no cutoff → token is accepted.
	if code := serve(BearerAuth(secret, stubChecker{active: true, before: nil}), token); code != 200 {
		t.Fatalf("valid token must pass, got %d", code)
	}
	// Cutoff after the token's iat → first-party token is revoked.
	cutoff := time.Now().Add(time.Second)
	if code := serve(BearerAuth(secret, stubChecker{active: true, before: &cutoff}), token); code != 401 {
		t.Fatalf("revoked token must be rejected, got %d", code)
	}
	// An OAuth token issued to an external app (has a client_id) must survive the
	// same cutoff: "sign out everywhere" must not knock external apps offline.
	extToken, _, err := issuer.IssueOAuthAccessToken(u, "external-app", "openid")
	if err != nil {
		t.Fatal(err)
	}
	if code := serve(BearerAuth(secret, stubChecker{active: true, before: &cutoff}), extToken); code != 200 {
		t.Fatalf("external-app token must not be revoked by cutoff, got %d", code)
	}
	// But a blocked account loses access immediately — even the external-app token.
	if code := serve(BearerAuth(secret, stubChecker{active: false}), extToken); code != 401 {
		t.Fatalf("blocked account's external token must be rejected, got %d", code)
	}
	if code := serve(BearerAuth(secret, stubChecker{active: false}), token); code != 401 {
		t.Fatalf("blocked account's first-party token must be rejected, got %d", code)
	}
}

func TestBearerAuthRejectsClientCredentialsToken(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	issuer := NewJWTIssuer(secret, 15*time.Minute)
	svc := users.User{ID: uuid.New(), Username: "service", Source: "client"}
	token, _, err := issuer.IssueClientCredentialsToken(svc, "service", "profile")
	if err != nil {
		t.Fatal(err)
	}
	// A service token (Purpose set) must never reach this SSO's own APIs.
	if code := serve(BearerAuth(secret, nil), token); code != 401 {
		t.Fatalf("client_credentials token must be rejected by BearerAuth, got %d", code)
	}
}
