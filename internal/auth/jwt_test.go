package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type stubChecker struct {
	active bool
	before *time.Time
}

func (s stubChecker) AccessState(_ context.Context, _ uuid.UUID) (bool, *time.Time, error) {
	return s.active, s.before, nil
}

type stubAccessVerifier struct {
	adminToken string
	claims     *Claims
}

func (s stubAccessVerifier) VerifyAdminAccessToken(_ context.Context, token string) (*Claims, error) {
	if token != s.adminToken {
		return nil, errors.New("wrong token class")
	}
	return s.claims, nil
}

func (stubAccessVerifier) VerifyOAuthAccessToken(_ context.Context, _, _ string) (*Claims, error) {
	return nil, errors.New("not used")
}

func serve(mw func(http.Handler) http.Handler, token string) int {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	return rec.Code
}

func TestBearerAuthHonoursTokenRevocation(t *testing.T) {
	issuedAt := time.Now().Add(-time.Minute)
	claims := &Claims{
		UserID: uuid.NewString(), TokenType: TokenTypeAdminAccess,
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(issuedAt)},
	}
	verifier := stubAccessVerifier{adminToken: "admin-token", claims: claims}

	if code := serve(BearerAuth(verifier, stubChecker{active: true}), "admin-token"); code != http.StatusOK {
		t.Fatalf("valid token must pass, got %d", code)
	}
	cutoff := issuedAt.Add(time.Second)
	if code := serve(BearerAuth(verifier, stubChecker{active: true, before: &cutoff}), "admin-token"); code != http.StatusUnauthorized {
		t.Fatalf("revoked token must be rejected, got %d", code)
	}
	if code := serve(BearerAuth(verifier, stubChecker{active: false}), "admin-token"); code != http.StatusUnauthorized {
		t.Fatalf("blocked account token must be rejected, got %d", code)
	}
}

func TestBearerAuthRejectsOtherTokenClasses(t *testing.T) {
	verifier := stubAccessVerifier{adminToken: "admin-token", claims: &Claims{UserID: uuid.NewString()}}
	if code := serve(BearerAuth(verifier, nil), "oauth-token"); code != http.StatusUnauthorized {
		t.Fatalf("OAuth token must be rejected by admin API, got %d", code)
	}
}
