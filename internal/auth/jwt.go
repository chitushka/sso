package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	TokenTypeAdminAccess       = "admin_access"
	TokenTypeOAuthAccess       = "oauth_access"
	TokenTypeClientCredentials = "client_credentials"
	TokenTypeMFA               = "mfa"
)

type Claims struct {
	UserID    string `json:"-"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Source    string `json:"source,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type JWTIssuer interface {
	Issue(ctx context.Context, u users.User) (string, time.Time, error)
	IssueOAuthAccessToken(ctx context.Context, u users.User, clientID, scope string) (string, time.Time, error)
	IssueClientCredentialsToken(ctx context.Context, u users.User, clientID, scope string) (string, time.Time, error)
}

type AccessTokenVerifier interface {
	VerifyAdminAccessToken(ctx context.Context, token string) (*Claims, error)
	VerifyOAuthAccessToken(ctx context.Context, token, audience string) (*Claims, error)
}

type claimsKey struct{}

type TokenChecker interface {
	AccessState(ctx context.Context, userID uuid.UUID) (active bool, invalidBefore *time.Time, err error)
}

func BearerAuth(verifier AccessTokenVerifier, revocations TokenChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				httpx.Error(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			if verifier == nil {
				httpx.Error(w, http.StatusUnauthorized, "invalid token")
				return
			}
			claims, err := verifier.VerifyAdminAccessToken(r.Context(), strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "invalid token")
				return
			}
			if revocations != nil {
				userID, err := uuid.Parse(claims.UserID)
				if err != nil {
					httpx.Error(w, http.StatusUnauthorized, "invalid token")
					return
				}
				active, invalidBefore, err := revocations.AccessState(r.Context(), userID)
				if err != nil {
					httpx.Error(w, http.StatusUnauthorized, "invalid token")
					return
				}
				if !active {
					httpx.Error(w, http.StatusUnauthorized, "account is not active")
					return
				}
				if invalidBefore != nil && (claims.IssuedAt == nil || !claims.IssuedAt.Time.After(*invalidBefore)) {
					httpx.Error(w, http.StatusUnauthorized, "token revoked")
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
		})
	}
}

func ClaimsFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(claimsKey{}).(*Claims)
	return v
}
