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

type stubChecker struct{ before *time.Time }

func (s stubChecker) TokensInvalidBefore(_ context.Context, _ uuid.UUID) (*time.Time, error) {
	return s.before, nil
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
	// No cutoff → token is accepted.
	if code := serve(BearerAuth(secret, stubChecker{before: nil}), token); code != 200 {
		t.Fatalf("valid token must pass, got %d", code)
	}
	// Cutoff after the token's iat → token is revoked.
	cutoff := time.Now().Add(time.Second)
	if code := serve(BearerAuth(secret, stubChecker{before: &cutoff}), token); code != 401 {
		t.Fatalf("revoked token must be rejected, got %d", code)
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
