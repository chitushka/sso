package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"math/big"
	"time"
)

type SigningKey struct {
	ID            uuid.UUID
	Kid           string
	Alg           string
	PrivateKeyPEM string
	PublicKeyPEM  string
	Status        string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
}
type KeyStore interface {
	ActiveKey(ctx context.Context) (SigningKey, error)
	Create(ctx context.Context, k SigningKey) (SigningKey, error)
	PublicKeys(ctx context.Context) ([]SigningKey, error)
}
type Service struct {
	issuer string
	keys   KeyStore
}

func NewService(issuer string, keys KeyStore) *Service { return &Service{issuer: issuer, keys: keys} }
func (s *Service) EnsureActiveKey(ctx context.Context) error {
	_, err := s.keys.ActiveKey(ctx)
	if err == nil {
		return nil
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	prv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pub := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})
	_, err = s.keys.Create(ctx, SigningKey{Kid: uuid.NewString(), Alg: "RS256", PrivateKeyPEM: string(prv), PublicKeyPEM: string(pub), Status: "active"})
	return err
}
func (s *Service) IssueIDToken(ctx context.Context, u users.User, clientID, nonce string, authTime time.Time) (string, error) {
	k, err := s.keys.ActiveKey(ctx)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(k.PrivateKeyPEM))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := jwt.MapClaims{"iss": s.issuer, "sub": u.ID.String(), "aud": clientID, "exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(), "auth_time": authTime.Unix(), "nonce": nonce, "email": u.Email, "preferred_username": u.Username}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = k.Kid
	return t.SignedString(priv)
}
func (s *Service) Discovery() map[string]any {
	return map[string]any{"issuer": s.issuer, "authorization_endpoint": s.issuer + "/oauth2/authorize", "token_endpoint": s.issuer + "/oauth2/token", "userinfo_endpoint": s.issuer + "/oauth2/userinfo", "jwks_uri": s.issuer + "/.well-known/jwks.json", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile", "email"}, "claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "preferred_username"}}
}
func (s *Service) JWKS(ctx context.Context) (map[string]any, error) {
	ks, err := s.keys.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, k := range ks {
		j, err := jwkFromRSA(k)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return map[string]any{"keys": out}, nil
}
func jwkFromRSA(k SigningKey) (map[string]any, error) {
	block, _ := pem.Decode([]byte(k.PublicKeyPEM))
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"kty": "RSA", "kid": k.Kid, "use": "sig", "alg": "RS256", "n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes())}, nil
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
