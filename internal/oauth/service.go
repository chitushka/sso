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
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
	"net/url"
	"strings"
	"time"
)

type IDTokenIssuer interface {
	IssueIDToken(ctx context.Context, u users.User, clientID, nonce string, authTime time.Time) (string, error)
}
type Service struct {
	repo     Repository
	users    users.Repository
	sessions auth.SessionRepository
	tokens   auth.JWTIssuer
	audit    audit.Repository
	secrets  auth.PasswordHasher
	idTokens IDTokenIssuer
}

var (
	ErrInvalidClient = errors.New("invalid client credentials")
	ErrInvalidScope  = errors.New("invalid_scope")
)

func NewService(repo Repository, users users.Repository, sessions auth.SessionRepository, tokens auth.JWTIssuer, audit audit.Repository, secrets auth.PasswordHasher) *Service {
	return &Service{repo: repo, users: users, sessions: sessions, tokens: tokens, audit: audit, secrets: secrets}
}
func (s *Service) WithIDTokenIssuer(i IDTokenIssuer) *Service { s.idTokens = i; return s }

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

type TokenInput struct{ GrantType, Code, RedirectURI, ClientID, ClientSecret, CodeVerifier string }
type TokenResult struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token,omitempty"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (s *Service) Token(ctx context.Context, in TokenInput) (TokenResult, error) {
	if in.GrantType != "authorization_code" {
		return TokenResult{}, errors.New("unsupported grant_type")
	}
	c, err := s.repo.FindClientByClientID(ctx, in.ClientID)
	if err != nil {
		return TokenResult{}, err
	}
	if c.Type == ClientConfidential {
		if c.ClientSecretHash == nil || in.ClientSecret == "" {
			return TokenResult{}, ErrInvalidClient
		}
		ok, err := s.secrets.Verify(in.ClientSecret, *c.ClientSecretHash)
		if err != nil || !ok {
			return TokenResult{}, ErrInvalidClient
		}
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
	access, exp, err := s.tokens.IssueOAuthAccessToken(u, c.ClientID, code.Scope)
	if err != nil {
		return TokenResult{}, err
	}
	var idt string
	if strings.Contains(" "+code.Scope+" ", " openid ") && s.idTokens != nil {
		idt, err = s.idTokens.IssueIDToken(ctx, u, c.ClientID, code.Nonce, code.CreatedAt)
		if err != nil {
			return TokenResult{}, err
		}
	}
	return TokenResult{AccessToken: access, IDToken: idt, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds())}, nil
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

var _ = uuid.Nil
var _ = storage.ErrNotFound
