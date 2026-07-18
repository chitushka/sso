package auth

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

type Claims struct {
	UserID   string `json:"sub"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Source   string `json:"source"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Purpose  string `json:"purpose,omitempty"` // "mfa" for the pending second-factor token
	jwt.RegisteredClaims
}
type JWTIssuer interface {
	Issue(u users.User) (string, time.Time, error)
	IssueOAuthAccessToken(u users.User, clientID, scope string) (string, time.Time, error)
	IssueClientCredentialsToken(u users.User, clientID, scope string) (string, time.Time, error)
}
type HMACJWTIssuer struct {
	secret []byte
	ttl    time.Duration
}

func NewJWTIssuer(secret []byte, ttl time.Duration) *HMACJWTIssuer {
	return &HMACJWTIssuer{secret: secret, ttl: ttl}
}
func (i *HMACJWTIssuer) Issue(u users.User) (string, time.Time, error) {
	return i.IssueOAuthAccessToken(u, "", "")
}

// IssueMFAToken issues the short-lived token bridging the password step and
// the TOTP step of a two-factor login. BearerAuth rejects it for API access.
func (i *HMACJWTIssuer) IssueMFAToken(u users.User) (string, error) {
	exp := time.Now().Add(5 * time.Minute)
	claims := Claims{UserID: u.ID.String(), Username: u.Username, Purpose: "mfa", RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID.String(), ExpiresAt: jwt.NewNumericDate(exp), IssuedAt: jwt.NewNumericDate(time.Now())}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
}
func (i *HMACJWTIssuer) VerifyMFAToken(tokenStr string) (string, error) {
	claims, err := i.Verify(tokenStr)
	if err != nil {
		return "", err
	}
	if claims.Purpose != "mfa" {
		return "", errors.New("not an mfa token")
	}
	return claims.UserID, nil
}
func (i *HMACJWTIssuer) Verify(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("invalid alg")
		}
		return i.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
func (i *HMACJWTIssuer) IssueOAuthAccessToken(u users.User, clientID, scope string) (string, time.Time, error) {
	exp := time.Now().Add(i.ttl)
	claims := Claims{UserID: u.ID.String(), Username: u.Username, Email: u.Email, Source: u.Source, ClientID: clientID, Scope: scope, RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID.String(), ExpiresAt: jwt.NewNumericDate(exp), IssuedAt: jwt.NewNumericDate(time.Now())}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(i.secret)
	return s, exp, err
}

// IssueClientCredentialsToken issues a service-account access token. It carries
// Purpose="client_credentials" so BearerAuth refuses it for this SSO's own APIs
// (those are for human users); it stays valid for external resource servers and
// for introspection.
func (i *HMACJWTIssuer) IssueClientCredentialsToken(u users.User, clientID, scope string) (string, time.Time, error) {
	exp := time.Now().Add(i.ttl)
	claims := Claims{UserID: u.ID.String(), Username: u.Username, Source: u.Source, ClientID: clientID, Scope: scope, Purpose: "client_credentials", RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID.String(), ExpiresAt: jwt.NewNumericDate(exp), IssuedAt: jwt.NewNumericDate(time.Now())}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(i.secret)
	return s, exp, err
}

type claimsKey struct{}

// TokenChecker gives BearerAuth the per-user state it needs to reject stale
// tokens: whether the account is still active (blocked/deleted accounts lose
// access immediately, including OAuth tokens held by external apps) and the
// cutoff before which first-party tokens are void ("sign out everywhere",
// password reset). nil = no revocation check (stateless). Both facts come from a
// single lookup so an authenticated request costs at most one extra query.
type TokenChecker interface {
	AccessState(ctx context.Context, userID uuid.UUID) (active bool, invalidBefore *time.Time, err error)
}

func BearerAuth(secret []byte, revocations TokenChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				httpx.Error(w, 401, "missing bearer token")
				return
			}
			tokenStr := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			claims := &Claims{}
			token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
				if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
					return nil, errors.New("invalid alg")
				}
				return secret, nil
			})
			if err != nil || !token.Valid {
				httpx.Error(w, 401, "invalid token")
				return
			}
			if claims.Purpose != "" {
				// Special-purpose tokens (mfa-pending, client_credentials) never
				// grant access to this SSO's own APIs.
				httpx.Error(w, 401, "invalid token")
				return
			}
			if revocations != nil {
				userID, perr := uuid.Parse(claims.UserID)
				if perr != nil {
					httpx.Error(w, 401, "invalid token")
					return
				}
				active, invBefore, cerr := revocations.AccessState(r.Context(), userID)
				if cerr != nil {
					httpx.Error(w, 401, "invalid token")
					return
				}
				// A blocked/deleted account loses access immediately — this
				// covers OAuth tokens held by external apps too (they carry a
				// client_id), not just first-party tokens.
				if !active {
					httpx.Error(w, 401, "account is not active")
					return
				}
				// The invalidation cutoff ("sign out everywhere", password reset)
				// applies only to first-party tokens (no client_id); external
				// apps' OAuth tokens keep their own lifetime/refresh.
				if claims.ClientID == "" && invBefore != nil && (claims.IssuedAt == nil || !claims.IssuedAt.Time.After(*invBefore)) {
					httpx.Error(w, 401, "token revoked")
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
