package auth

import (
	"time"

	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
)

type JWTIssuer struct {
	secret []byte
	ttl    time.Duration
}

func NewJWTIssuer(secret []byte, ttl time.Duration) JWTIssuer {
	return JWTIssuer{secret: secret, ttl: ttl}
}

type Claims struct {
	UserID   string `json:"uid"`
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.RegisteredClaims
}

func (i JWTIssuer) Issue(u users.User) (string, time.Time, error) {
	expires := time.Now().Add(i.ttl)
	claims := Claims{UserID: u.ID.String(), Username: u.Username, Email: u.Email, RegisteredClaims: jwt.RegisteredClaims{Subject: u.ID.String(), ExpiresAt: jwt.NewNumericDate(expires), IssuedAt: jwt.NewNumericDate(time.Now()), Issuer: "chitushka-sso"}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := token.SignedString(i.secret)
	return s, expires, err
}
func ParseToken(secret []byte, raw string) (*Claims, error) {
	claims := &Claims{}
	t, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) { return secret, nil }, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, jwt.ErrTokenInvalidClaims
	}
	return claims, nil
}
