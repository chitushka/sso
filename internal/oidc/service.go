package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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
	MarkRetiring(ctx context.Context, id uuid.UUID, expiresAt time.Time) error
	RetireExpired(ctx context.Context) error
}
type Service struct {
	issuer string
	keys   KeyStore
}

func NewService(issuer string, keys KeyStore) *Service { return &Service{issuer: issuer, keys: keys} }

// Rotation policy: a new active key is generated once the current one exceeds
// keyMaxAge; the old key stays in JWKS as "retiring" for retireGrace so
// already-issued ID tokens (15m TTL) remain verifiable.
const (
	keyMaxAge             = 30 * 24 * time.Hour
	retireGrace           = 24 * time.Hour
	rotationCheckInterval = time.Hour
	// maxLogoutHintAge bounds how long an id_token_hint stays usable for
	// RP-initiated logout after it was issued.
	maxLogoutHintAge = 24 * time.Hour
)

func (s *Service) EnsureActiveKey(ctx context.Context) error {
	_, err := s.keys.ActiveKey(ctx)
	if err == nil {
		return nil
	}
	return s.generateActiveKey(ctx)
}
func (s *Service) generateActiveKey(ctx context.Context) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	prv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pub := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})
	_, err = s.keys.Create(ctx, SigningKey{Kid: uuid.NewString(), Alg: "RS256", PrivateKeyPEM: string(prv), PublicKeyPEM: string(pub), Status: "active"})
	return err
}
func (s *Service) RotateIfNeeded(ctx context.Context) error {
	if err := s.keys.RetireExpired(ctx); err != nil {
		return err
	}
	k, err := s.keys.ActiveKey(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		return s.generateActiveKey(ctx)
	}
	if err != nil {
		return err
	}
	if time.Since(k.CreatedAt) < keyMaxAge {
		return nil
	}
	if err := s.keys.MarkRetiring(ctx, k.ID, time.Now().Add(retireGrace)); err != nil {
		return err
	}
	return s.generateActiveKey(ctx)
}

// StartRotation runs the rotation check in the background until ctx is cancelled.
func (s *Service) StartRotation(ctx context.Context, logger *slog.Logger) {
	go func() {
		t := time.NewTicker(rotationCheckInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.RotateIfNeeded(ctx); err != nil {
					logger.Error("oidc key rotation", "error", err)
				}
			}
		}
	}()
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

// VerifyIDToken validates an id_token_hint (RS256 signature via stored public
// keys, issuer match) and returns its subject and audience.
func (s *Service) VerifyIDToken(ctx context.Context, raw string) (string, string, error) {
	keys, err := s.keys.PublicKeys(ctx)
	if err != nil {
		return "", "", err
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("invalid alg")
		}
		kid, _ := t.Header["kid"].(string)
		for _, k := range keys {
			if k.Kid == kid {
				block, _ := pem.Decode([]byte(k.PublicKeyPEM))
				return x509.ParsePKCS1PublicKey(block.Bytes)
			}
		}
		return nil, errors.New("unknown kid")
	}, jwt.WithIssuer(s.issuer), jwt.WithoutClaimsValidation())
	if err != nil || !token.Valid {
		return "", "", errors.New("invalid id token")
	}
	// Expiry itself is deliberately not enforced (RP-initiated logout allows an
	// expired hint), but the hint must not be usable forever: bound its age via
	// iat so a leaked id_token cannot drive logout indefinitely.
	if iss, _ := claims["iss"].(string); iss != s.issuer {
		return "", "", errors.New("invalid issuer")
	}
	if iat, ok := claims["iat"].(float64); ok {
		if time.Since(time.Unix(int64(iat), 0)) > maxLogoutHintAge {
			return "", "", errors.New("id token hint too old")
		}
	}
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	if sub == "" || aud == "" {
		return "", "", errors.New("missing sub or aud")
	}
	return sub, aud, nil
}

// IssueLogoutToken builds an OIDC back-channel logout token (RS256).
func (s *Service) IssueLogoutToken(ctx context.Context, sub, clientID string) (string, error) {
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
	claims := jwt.MapClaims{
		"iss":    s.issuer,
		"sub":    sub,
		"aud":    clientID,
		"iat":    now.Unix(),
		"exp":    now.Add(2 * time.Minute).Unix(),
		"jti":    uuid.NewString(),
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = k.Kid
	return t.SignedString(priv)
}

// SendBackchannelLogout POSTs a logout_token to the client's registered URI
// (OIDC Back-Channel Logout 1.0).
func (s *Service) SendBackchannelLogout(ctx context.Context, sub, clientID, uri string) error {
	logoutToken, err := s.IssueLogoutToken(ctx, sub, clientID)
	if err != nil {
		return err
	}
	form := url.Values{"logout_token": {logoutToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return errors.New("backchannel logout rejected: " + resp.Status)
	}
	return nil
}

func (s *Service) Discovery() map[string]any {
	return map[string]any{"issuer": s.issuer, "authorization_endpoint": s.issuer + "/oauth2/authorize", "token_endpoint": s.issuer + "/oauth2/token", "userinfo_endpoint": s.issuer + "/oauth2/userinfo", "revocation_endpoint": s.issuer + "/oauth2/revoke", "introspection_endpoint": s.issuer + "/oauth2/introspect", "end_session_endpoint": s.issuer + "/oauth2/logout", "jwks_uri": s.issuer + "/.well-known/jwks.json", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "scopes_supported": []string{"openid", "profile", "email"}, "claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "preferred_username"}, "backchannel_logout_supported": true}
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
