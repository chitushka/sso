package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
	"net/url"
	"strings"
	"time"
)

type IDTokenIssuer interface {
	IssueIDToken(ctx context.Context, u users.User, clientID, nonce string, authTime time.Time) (string, error)
}
type TokenVerifier interface {
	Verify(token string) (*auth.Claims, error)
}
type Service struct {
	repo       Repository
	users      users.Repository
	sessions   auth.SessionRepository
	tokens     auth.JWTIssuer
	audit      audit.Repository
	secrets    auth.PasswordHasher
	idTokens   IDTokenIssuer
	verifier   TokenVerifier
	refreshTTL time.Duration
}

var (
	ErrInvalidClient = errors.New("invalid client credentials")
	ErrInvalidScope  = errors.New("invalid_scope")
	ErrInvalidGrant  = errors.New("invalid_grant")
)

func NewService(repo Repository, users users.Repository, sessions auth.SessionRepository, tokens auth.JWTIssuer, audit audit.Repository, secrets auth.PasswordHasher) *Service {
	return &Service{repo: repo, users: users, sessions: sessions, tokens: tokens, audit: audit, secrets: secrets, refreshTTL: 720 * time.Hour}
}
func (s *Service) WithIDTokenIssuer(i IDTokenIssuer) *Service { s.idTokens = i; return s }
func (s *Service) WithTokenVerifier(v TokenVerifier) *Service { s.verifier = v; return s }
func (s *Service) WithRefreshTTL(d time.Duration) *Service    { s.refreshTTL = d; return s }

type CreateClientInput struct {
	ClientID      string     `json:"client_id"`
	Name          string     `json:"name"`
	Type          ClientType `json:"type"`
	RedirectURIs  []string   `json:"redirect_uris"`
	AllowedScopes []string   `json:"allowed_scopes"`
	Enabled       bool       `json:"enabled"`
}
type CreateClientResult struct {
	Client       Client `json:"client"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func (s *Service) CreateClient(ctx context.Context, in CreateClientInput) (CreateClientResult, error) {
	if in.Type == "" {
		in.Type = ClientConfidential
	}
	c, sec, err := s.repo.CreateClient(ctx, Client{ClientID: in.ClientID, Name: in.Name, Type: in.Type, RedirectURIs: in.RedirectURIs, AllowedScopes: in.AllowedScopes, Enabled: in.Enabled})
	return CreateClientResult{Client: c, ClientSecret: sec}, err
}
func (s *Service) ListClients(ctx context.Context) ([]Client, error) { return s.repo.ListClients(ctx) }

type UpdateClientInput struct {
	Name          string   `json:"name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	Enabled       bool     `json:"enabled"`
}

func (s *Service) UpdateClient(ctx context.Context, id uuid.UUID, in UpdateClientInput) (Client, error) {
	c, err := s.repo.UpdateClient(ctx, Client{ID: id, Name: in.Name, RedirectURIs: in.RedirectURIs, AllowedScopes: in.AllowedScopes, Enabled: in.Enabled})
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "oauth_client_updated", TargetType: "oauth_client", TargetID: c.ClientID})
	}
	return c, err
}
func (s *Service) DeleteClient(ctx context.Context, id uuid.UUID) error {
	err := s.repo.DeleteClient(ctx, id)
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "oauth_client_deleted", TargetType: "oauth_client", TargetID: id.String()})
	}
	return err
}

type AuthorizeInput struct{ ResponseType, ClientID, RedirectURI, Scope, State, CodeChallenge, CodeChallengeMethod, Nonce, SessionToken string }
type AuthorizeResult struct {
	Redirect string `json:"redirect"`
	Code     string `json:"code"`
	State    string `json:"state,omitempty"`
}

func (s *Service) Authorize(ctx context.Context, in AuthorizeInput) (AuthorizeResult, error) {
	if in.ResponseType != "code" {
		return AuthorizeResult{}, errors.New("unsupported response_type")
	}
	c, err := s.repo.FindClientByClientID(ctx, in.ClientID)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if !c.Enabled {
		return AuthorizeResult{}, errors.New("client disabled")
	}
	if !contains(c.RedirectURIs, in.RedirectURI) {
		return AuthorizeResult{}, errors.New("invalid redirect_uri")
	}
	if err := validateScope(in.Scope, c.AllowedScopes); err != nil {
		return AuthorizeResult{}, err
	}
	if c.Type == ClientPublic && (in.CodeChallenge == "" || in.CodeChallengeMethod != "S256") {
		return AuthorizeResult{}, errors.New("PKCE S256 required")
	}
	sess, err := s.sessions.FindByTokenHash(ctx, auth.HashSessionToken(in.SessionToken))
	if err != nil || sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return AuthorizeResult{}, errors.New("login required")
	}
	raw, hash, err := newCode()
	if err != nil {
		return AuthorizeResult{}, err
	}
	_, err = s.repo.CreateCode(ctx, AuthorizationCode{CodeHash: hash, ClientID: c.ClientID, UserID: sess.UserID, RedirectURI: in.RedirectURI, Scope: in.Scope, CodeChallenge: in.CodeChallenge, CodeChallengeMethod: in.CodeChallengeMethod, Nonce: in.Nonce, ExpiresAt: time.Now().Add(5 * time.Minute)})
	if err != nil {
		return AuthorizeResult{}, err
	}
	u, _ := url.Parse(in.RedirectURI)
	q := u.Query()
	q.Set("code", raw)
	if in.State != "" {
		q.Set("state", in.State)
	}
	u.RawQuery = q.Encode()
	return AuthorizeResult{Redirect: u.String(), Code: raw, State: in.State}, nil
}

type TokenInput struct {
	GrantType, Code, RedirectURI, ClientID, ClientSecret, CodeVerifier, RefreshToken string
}
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

func (s *Service) Token(ctx context.Context, in TokenInput) (TokenResult, error) {
	switch in.GrantType {
	case "authorization_code":
		return s.codeGrant(ctx, in)
	case "refresh_token":
		return s.refreshGrant(ctx, in)
	default:
		return TokenResult{}, errors.New("unsupported grant_type")
	}
}
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (Client, error) {
	c, err := s.repo.FindClientByClientID(ctx, clientID)
	if err != nil || !c.Enabled {
		return Client{}, ErrInvalidClient
	}
	if c.Type == ClientConfidential {
		if c.ClientSecretHash == nil || clientSecret == "" {
			return Client{}, ErrInvalidClient
		}
		ok, err := s.secrets.Verify(clientSecret, *c.ClientSecretHash)
		if err != nil || !ok {
			return Client{}, ErrInvalidClient
		}
	}
	return c, nil
}
func (s *Service) codeGrant(ctx context.Context, in TokenInput) (TokenResult, error) {
	c, err := s.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return TokenResult{}, err
	}
	code, err := s.repo.ConsumeCode(ctx, hashCode(in.Code))
	if err != nil {
		return TokenResult{}, err
	}
	if time.Now().After(code.ExpiresAt) {
		return TokenResult{}, errors.New("code expired")
	}
	if code.ClientID != in.ClientID || code.RedirectURI != in.RedirectURI {
		return TokenResult{}, errors.New("invalid code")
	}
	if code.CodeChallenge != "" && !VerifyPKCES256(in.CodeVerifier, code.CodeChallenge) {
		return TokenResult{}, errors.New("invalid pkce verifier")
	}
	u, err := s.users.FindByID(ctx, code.UserID)
	if err != nil {
		return TokenResult{}, err
	}
	return s.issue(ctx, u, c, code.Scope, code.Nonce, code.CreatedAt, uuid.New())
}
func (s *Service) refreshGrant(ctx context.Context, in TokenInput) (TokenResult, error) {
	c, err := s.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return TokenResult{}, err
	}
	if in.RefreshToken == "" {
		return TokenResult{}, ErrInvalidGrant
	}
	rt, err := s.repo.FindRefreshTokenByHash(ctx, hashCode(in.RefreshToken))
	if err != nil || rt.ClientID != c.ClientID {
		return TokenResult{}, ErrInvalidGrant
	}
	if rt.RevokedAt != nil || time.Now().After(rt.ExpiresAt) {
		return TokenResult{}, ErrInvalidGrant
	}
	if rt.RotatedAt != nil {
		// Reuse of an already-rotated token means it leaked: kill the whole family.
		_ = s.repo.RevokeRefreshFamily(ctx, rt.FamilyID)
		_ = s.audit.Write(ctx, audit.Event{Action: "refresh_token_reuse_detected", TargetType: "oauth_client", TargetID: c.ClientID})
		return TokenResult{}, ErrInvalidGrant
	}
	u, err := s.users.FindByID(ctx, rt.UserID)
	if err != nil || u.Status != users.StatusActive {
		_ = s.repo.RevokeRefreshFamily(ctx, rt.FamilyID)
		return TokenResult{}, ErrInvalidGrant
	}
	if err := s.repo.MarkRefreshTokenRotated(ctx, rt.ID); err != nil {
		return TokenResult{}, err
	}
	return s.issue(ctx, u, c, rt.Scope, "", rt.CreatedAt, rt.FamilyID)
}
func (s *Service) issue(ctx context.Context, u users.User, c Client, scope, nonce string, authTime time.Time, family uuid.UUID) (TokenResult, error) {
	access, exp, err := s.tokens.IssueOAuthAccessToken(u, c.ClientID, scope)
	if err != nil {
		return TokenResult{}, err
	}
	rawRefresh, refreshHash, err := newCode()
	if err != nil {
		return TokenResult{}, err
	}
	if _, err := s.repo.CreateRefreshToken(ctx, RefreshToken{TokenHash: refreshHash, FamilyID: family, UserID: u.ID, ClientID: c.ClientID, Scope: scope, ExpiresAt: time.Now().Add(s.refreshTTL)}); err != nil {
		return TokenResult{}, err
	}
	var idt string
	if strings.Contains(" "+scope+" ", " openid ") && s.idTokens != nil {
		idt, err = s.idTokens.IssueIDToken(ctx, u, c.ClientID, nonce, authTime)
		if err != nil {
			return TokenResult{}, err
		}
	}
	return TokenResult{AccessToken: access, RefreshToken: rawRefresh, IDToken: idt, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds()), Scope: scope}, nil
}

type RevokeInput struct{ Token, ClientID, ClientSecret string }

// Revoke implements RFC 7009: unknown or foreign tokens are ignored (200),
// only failed client authentication is an error.
func (s *Service) Revoke(ctx context.Context, in RevokeInput) error {
	c, err := s.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return err
	}
	rt, err := s.repo.FindRefreshTokenByHash(ctx, hashCode(in.Token))
	if err != nil || rt.ClientID != c.ClientID {
		return nil
	}
	if err := s.repo.RevokeRefreshFamily(ctx, rt.FamilyID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "refresh_token_revoked", TargetType: "oauth_client", TargetID: c.ClientID})
	return nil
}

type IntrospectInput struct{ Token, ClientID, ClientSecret string }

// Introspect implements RFC 7662 for refresh tokens (stored) and access tokens (JWT).
func (s *Service) Introspect(ctx context.Context, in IntrospectInput) (map[string]any, error) {
	if _, err := s.authenticateClient(ctx, in.ClientID, in.ClientSecret); err != nil {
		return nil, err
	}
	inactive := map[string]any{"active": false}
	if rt, err := s.repo.FindRefreshTokenByHash(ctx, hashCode(in.Token)); err == nil {
		if rt.RevokedAt != nil || rt.RotatedAt != nil || time.Now().After(rt.ExpiresAt) {
			return inactive, nil
		}
		return map[string]any{"active": true, "token_type": "refresh_token", "client_id": rt.ClientID, "sub": rt.UserID.String(), "scope": rt.Scope, "exp": rt.ExpiresAt.Unix(), "iat": rt.CreatedAt.Unix()}, nil
	}
	if s.verifier != nil {
		if claims, err := s.verifier.Verify(in.Token); err == nil {
			out := map[string]any{"active": true, "token_type": "Bearer", "client_id": claims.ClientID, "sub": claims.UserID, "username": claims.Username, "scope": claims.Scope}
			if claims.ExpiresAt != nil {
				out["exp"] = claims.ExpiresAt.Unix()
			}
			return out, nil
		}
	}
	return inactive, nil
}
func newCode() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	return raw, hashCode(raw), nil
}
func hashCode(code string) string { s := sha256.Sum256([]byte(code)); return hex.EncodeToString(s[:]) }
func validateScope(requested string, allowed []string) error {
	for _, sc := range strings.Fields(requested) {
		if !contains(allowed, sc) {
			return ErrInvalidScope
		}
	}
	return nil
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
