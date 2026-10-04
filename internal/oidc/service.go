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

	"github.com/chitushka/sso/internal/auth"
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
	EnsureActive(ctx context.Context, candidate SigningKey) (SigningKey, error)
	Rotate(ctx context.Context, currentID uuid.UUID, candidate SigningKey, retiringExpiresAt time.Time) error
	PublicKeys(ctx context.Context) ([]SigningKey, error)
	RetireExpired(ctx context.Context) error
}
type Service struct {
	issuer    string
	keys      KeyStore
	client    *http.Client
	accessTTL time.Duration
	newKey    func() (SigningKey, error)
}

func NewService(issuer string, keys KeyStore) *Service {
	return &Service{issuer: strings.TrimRight(issuer, "/"), keys: keys, client: newBackchannelHTTPClient(), accessTTL: 15 * time.Minute, newKey: generateSigningKey}
}

func (s *Service) WithAccessTokenTTL(ttl time.Duration) *Service {
	s.accessTTL = ttl
	return s
}

// Rotation policy: a new active key is generated once the current one exceeds
// keyMaxAge; the old key stays in JWKS as "retiring" for at least retireGrace
// and never less than the configured access-token lifetime.
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
	if !errors.Is(err, storage.ErrNotFound) {
		return err
	}
	candidate, err := s.newKey()
	if err != nil {
		return err
	}
	_, err = s.keys.EnsureActive(ctx, candidate)
	return err
}
func generateSigningKey() (SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return SigningKey{}, err
	}
	prv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pub := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey)})
	return SigningKey{Kid: uuid.NewString(), Alg: "RS256", PrivateKeyPEM: string(prv), PublicKeyPEM: string(pub), Status: "active"}, nil
}
func (s *Service) RotateIfNeeded(ctx context.Context) error {
	if err := s.keys.RetireExpired(ctx); err != nil {
		return err
	}
	k, err := s.keys.ActiveKey(ctx)
	if errors.Is(err, storage.ErrNotFound) {
		return s.EnsureActiveKey(ctx)
	}
	if err != nil {
		return err
	}
	if time.Since(k.CreatedAt) < keyMaxAge {
		return nil
	}
	candidate, err := s.newKey()
	if err != nil {
		return err
	}
	grace := retireGrace
	if minimum := s.accessTTL + time.Minute; minimum > grace {
		grace = minimum
	}
	return s.keys.Rotate(ctx, k.ID, candidate, time.Now().Add(grace))
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

func (s *Service) adminAudience() string { return s.issuer + "/api/v1" }
func (s *Service) mfaAudience() string   { return s.issuer + "/api/v1/auth/mfa" }

func (s *Service) Issue(ctx context.Context, u users.User) (string, time.Time, error) {
	return s.issueAccessToken(ctx, u, s.adminAudience(), "", "", auth.TokenTypeAdminAccess, s.accessTTL, "at+jwt")
}

func (s *Service) IssueOAuthAccessToken(ctx context.Context, u users.User, clientID, scope string) (string, time.Time, error) {
	return s.issueAccessToken(ctx, u, clientID, clientID, scope, auth.TokenTypeOAuthAccess, s.accessTTL, "at+jwt")
}

func (s *Service) IssueClientCredentialsToken(ctx context.Context, u users.User, clientID, scope string) (string, time.Time, error) {
	return s.issueAccessToken(ctx, u, clientID, clientID, scope, auth.TokenTypeClientCredentials, s.accessTTL, "at+jwt")
}

func (s *Service) IssueMFAToken(ctx context.Context, u users.User) (string, error) {
	raw, _, err := s.issueAccessToken(ctx, u, s.mfaAudience(), "", "", auth.TokenTypeMFA, 5*time.Minute, "mfa+jwt")
	return raw, err
}

func (s *Service) issueAccessToken(ctx context.Context, u users.User, audience, clientID, scope, tokenType string, ttl time.Duration, headerType string) (string, time.Time, error) {
	if audience == "" {
		return "", time.Time{}, errors.New("token audience is required")
	}
	k, err := s.keys.ActiveKey(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	priv, err := parsePrivateKey(k.PrivateKeyPEM)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := auth.Claims{
		UserID: u.ID.String(), Username: u.Username, Email: u.Email, Source: u.Source,
		ClientID: clientID, Scope: scope, TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: s.issuer, Subject: u.ID.String(), Audience: jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt), IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), ID: uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = k.Kid
	token.Header["typ"] = headerType
	raw, err := token.SignedString(priv)
	return raw, expiresAt, err
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("invalid OIDC private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (s *Service) VerifyAdminAccessToken(ctx context.Context, raw string) (*auth.Claims, error) {
	return s.verifyAccessToken(ctx, raw, s.adminAudience(), "at+jwt", auth.TokenTypeAdminAccess)
}

func (s *Service) VerifyOAuthAccessToken(ctx context.Context, raw, audience string) (*auth.Claims, error) {
	return s.verifyAccessToken(ctx, raw, audience, "at+jwt", auth.TokenTypeOAuthAccess, auth.TokenTypeClientCredentials)
}

func (s *Service) VerifyMFAToken(ctx context.Context, raw string) (string, error) {
	claims, err := s.verifyAccessToken(ctx, raw, s.mfaAudience(), "mfa+jwt", auth.TokenTypeMFA)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}

func (s *Service) verifyAccessToken(ctx context.Context, raw, audience, headerType string, allowedTypes ...string) (*auth.Claims, error) {
	if audience == "" {
		return nil, errors.New("token audience is required")
	}
	keys, err := s.keys.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	claims := &auth.Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("invalid token algorithm")
		}
		if typ, _ := token.Header["typ"].(string); typ != headerType {
			return nil, errors.New("invalid token header type")
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		for _, key := range keys {
			if key.Kid == kid && key.Alg == "RS256" {
				return parsePublicKey(key.PublicKeyPEM)
			}
		}
		return nil, errors.New("unknown kid")
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(30*time.Second))
	if err != nil || !token.Valid || claims.Subject == "" || claims.IssuedAt == nil {
		return nil, errors.New("invalid access token")
	}
	allowed := false
	for _, tokenType := range allowedTypes {
		if claims.TokenType == tokenType {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("invalid token type")
	}
	claims.UserID = claims.Subject
	return claims, nil
}

func parsePublicKey(raw string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("invalid OIDC public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func (s *Service) IssueIDToken(ctx context.Context, u users.User, clientID, nonce string, authTime time.Time) (string, error) {
	k, err := s.keys.ActiveKey(ctx)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode([]byte(k.PrivateKeyPEM))
	if block == nil {
		return "", errors.New("invalid OIDC private key")
	}
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
				if block == nil {
					return nil, errors.New("invalid OIDC public key")
				}
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
	if block == nil {
		return "", errors.New("invalid OIDC private key")
	}
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
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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
	if block == nil {
		return nil, errors.New("invalid OIDC public key")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return map[string]any{"kty": "RSA", "kid": k.Kid, "use": "sig", "alg": "RS256", "n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes())}, nil
}
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
