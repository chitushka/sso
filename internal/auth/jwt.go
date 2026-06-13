package auth

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/httpx"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
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
	jwt.RegisteredClaims
}
type JWTIssuer interface {
	Issue(u users.User) (string, time.Time, error)
	IssueOAuthAccessToken(u users.User, clientID, scope string) (string, time.Time, error)
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
func (i *HMACJWTIssuer) IssueOAuthAccessToken(u users.User, clientID, scope string) (string, time.Time, error) {
	exp := time.Now().Add(i.ttl)
	claims := Claims{UserID: u.ID.String(), Username: u.Username, Email: u.Email, Source: u.Source, ClientID: clientID, Scope: scope, RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID.String(), ExpiresAt: jwt.NewNumericDate(exp), IssuedAt: jwt.NewNumericDate(time.Now())}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(i.secret)
	return s, exp, err
}

type claimsKey struct{}

func BearerAuth(secret []byte) func(http.Handler) http.Handler {
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
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
		})
	}
}
func ClaimsFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(claimsKey{}).(*Claims)
	return v
}
