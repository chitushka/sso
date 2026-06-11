package oauth

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

type Service struct {
	repo      Repository
	users     users.Repository
	sessions  auth.SessionRepository
	audit     audit.Repository
	passwords PasswordHasher
	jwtSecret []byte
	accessTTL time.Duration
	codeTTL   time.Duration
	issuer    string
}

func NewService(repo Repository, users users.Repository, sessions auth.SessionRepository, audit audit.Repository, passwords PasswordHasher, jwtSecret []byte, accessTTL time.Duration) *Service {
	return &Service{repo: repo, users: users, sessions: sessions, audit: audit, passwords: passwords, jwtSecret: jwtSecret, accessTTL: accessTTL, codeTTL: 5 * time.Minute, issuer: "chitushka-sso"}
}

var (
	ErrInvalidClient       = errors.New("invalid client")
	ErrInvalidRedirectURI  = errors.New("invalid redirect_uri")
	ErrUnsupportedResponse = errors.New("unsupported response_type")
	ErrUnsupportedGrant    = errors.New("unsupported grant_type")
	ErrLoginRequired       = errors.New("login required")
	ErrInvalidCode         = errors.New("invalid authorization code")
	ErrInvalidScope        = errors.New("invalid scope")
)

type AuthorizeInput struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionToken        string
	IP                  string
	UserAgent           string
}

type AuthorizeResult struct {
	RedirectURI string
	Code        string
	State       string
}

type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	IP           string
	UserAgent    string
}

func (s *Service) CreateClient(ctx context.Context, in CreateClientInput, ip, ua string) (Client, string, error) {
	if strings.TrimSpace(in.ClientID) == "" || strings.TrimSpace(in.Name) == "" {
		return Client{}, "", errors.New("client_id and name are required")
	}
	if in.Type == "" {
		in.Type = ClientTypeConfidential
	}
	if in.Type != ClientTypeConfidential && in.Type != ClientTypePublic {
		return Client{}, "", errors.New("invalid client type")
	}
	if len(in.RedirectURIs) == 0 {
		return Client{}, "", errors.New("at least one redirect_uri is required")
	}
	for _, redirectURI := range in.RedirectURIs {
		if _, err := url.ParseRequestURI(redirectURI); err != nil {
			return Client{}, "", errors.New("invalid redirect_uri")
		}
	}
	if len(in.AllowedScopes) == 0 {
		in.AllowedScopes = []string{"read"}
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	secretPlain := ""
	secretHash := ""
	if in.Type == ClientTypeConfidential {
		if in.ClientSecret == "" {
			var err error
			secretPlain, err = generateClientSecret()
			if err != nil {
				return Client{}, "", err
			}
		} else {
			secretPlain = in.ClientSecret
		}
		h, err := s.passwords.Hash(secretPlain)
		if err != nil {
			return Client{}, "", err
		}
		secretHash = h
	}
	created, err := s.repo.CreateClient(ctx, Client{ClientID: in.ClientID, ClientSecretHash: secretHash, Name: in.Name, Type: in.Type, RedirectURIs: in.RedirectURIs, AllowedScopes: in.AllowedScopes, Enabled: enabled})
	if err != nil {
		return Client{}, "", err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "oauth_client_created", TargetType: "oauth_client", TargetID: created.ID.String(), IP: ip, UserAgent: ua})
	return created, secretPlain, nil
}

func (s *Service) ListClients(ctx context.Context, limit, offset int) ([]Client, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListClients(ctx, limit, offset)
}

func (s *Service) GetClient(ctx context.Context, id uuid.UUID) (Client, error) {
	return s.repo.FindClientByID(ctx, id)
}

func (s *Service) UpdateClient(ctx context.Context, id uuid.UUID, in UpdateClientInput) (Client, error) {
	current, err := s.repo.FindClientByID(ctx, id)
	if err != nil {
		return Client{}, err
	}
	if strings.TrimSpace(in.Name) != "" {
		current.Name = in.Name
	}
	if in.Type != "" {
		if in.Type != ClientTypeConfidential && in.Type != ClientTypePublic {
			return Client{}, errors.New("invalid client type")
		}
		current.Type = in.Type
	}
	if len(in.RedirectURIs) > 0 {
		current.RedirectURIs = in.RedirectURIs
	}
	if len(in.AllowedScopes) > 0 {
		current.AllowedScopes = in.AllowedScopes
	}
	if in.Enabled != nil {
		current.Enabled = *in.Enabled
	}
	return s.repo.UpdateClient(ctx, current)
}

func (s *Service) DeleteClient(ctx context.Context, id uuid.UUID) error {
	return s.repo.DeleteClient(ctx, id)
}

func (s *Service) Authorize(ctx context.Context, in AuthorizeInput) (AuthorizeResult, error) {
	if in.ResponseType != "code" {
		return AuthorizeResult{}, ErrUnsupportedResponse
	}
	client, err := s.repo.FindClientByClientID(ctx, in.ClientID)
	if err != nil || !client.Enabled {
		return AuthorizeResult{}, ErrInvalidClient
	}
	if !slices.Contains(client.RedirectURIs, in.RedirectURI) {
		return AuthorizeResult{}, ErrInvalidRedirectURI
	}
	scope := normalizeScope(in.Scope)
	if scope == "" {
		scope = "read"
	}
	if !scopeAllowed(scope, client.AllowedScopes) {
		return AuthorizeResult{}, ErrInvalidScope
	}
	if client.Type == ClientTypePublic {
		if in.CodeChallenge == "" || in.CodeChallengeMethod != "S256" {
			return AuthorizeResult{}, ErrInvalidPKCE
		}
	}
	u, err := s.userFromSession(ctx, in.SessionToken)
	if err != nil {
		return AuthorizeResult{}, ErrLoginRequired
	}
	rawCode, codeHash, err := NewAuthorizationCode()
	if err != nil {
		return AuthorizeResult{}, err
	}
	_, err = s.repo.CreateAuthorizationCode(ctx, AuthorizationCode{CodeHash: codeHash, ClientID: client.ID, UserID: u.ID, RedirectURI: in.RedirectURI, Scope: scope, CodeChallenge: in.CodeChallenge, CodeChallengeMethod: in.CodeChallengeMethod, ExpiresAt: time.Now().Add(s.codeTTL)})
	if err != nil {
		return AuthorizeResult{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "oauth_authorization_code_issued", TargetType: "oauth_client", TargetID: client.ID.String(), IP: in.IP, UserAgent: in.UserAgent})
	return AuthorizeResult{RedirectURI: in.RedirectURI, Code: rawCode, State: in.State}, nil
}

func (s *Service) ExchangeCode(ctx context.Context, in TokenInput) (TokenResponse, error) {
	if in.GrantType != "authorization_code" {
		return TokenResponse{}, ErrUnsupportedGrant
	}
	client, err := s.repo.FindClientByClientID(ctx, in.ClientID)
	if err != nil || !client.Enabled {
		return TokenResponse{}, ErrInvalidClient
	}
	if client.Type == ClientTypeConfidential {
		ok, err := s.passwords.Verify(in.ClientSecret, client.ClientSecretHash)
		if err != nil || !ok {
			return TokenResponse{}, ErrInvalidClient
		}
	}
	code, err := s.repo.FindAuthorizationCodeByHash(ctx, HashCode(in.Code))
	if err != nil {
		return TokenResponse{}, ErrInvalidCode
	}
	if code.ClientID != client.ID || code.RedirectURI != in.RedirectURI || code.UsedAt != nil || time.Now().After(code.ExpiresAt) {
		return TokenResponse{}, ErrInvalidCode
	}
	if code.CodeChallenge != "" {
		if code.CodeChallengeMethod != "S256" || VerifyPKCES256(in.CodeVerifier, code.CodeChallenge) != nil {
			return TokenResponse{}, ErrInvalidPKCE
		}
	}
	if err := s.repo.MarkAuthorizationCodeUsed(ctx, code.ID); err != nil {
		return TokenResponse{}, err
	}
	u, err := s.users.FindByID(ctx, code.UserID)
	if err != nil {
		return TokenResponse{}, err
	}
	access, exp, err := s.issueAccessToken(u, client, code.Scope)
	if err != nil {
		return TokenResponse{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "oauth_token_issued", TargetType: "oauth_client", TargetID: client.ID.String(), IP: in.IP, UserAgent: in.UserAgent})
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds()), Scope: code.Scope}, nil
}

func (s *Service) userFromSession(ctx context.Context, rawSessionToken string) (users.User, error) {
	if rawSessionToken == "" {
		return users.User{}, ErrLoginRequired
	}
	sess, err := s.sessions.FindByTokenHash(ctx, auth.HashSessionToken(rawSessionToken))
	if err != nil {
		return users.User{}, err
	}
	if sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return users.User{}, ErrLoginRequired
	}
	u, err := s.users.FindByID(ctx, sess.UserID)
	if err != nil {
		return users.User{}, err
	}
	if u.Status != users.StatusActive {
		return users.User{}, ErrLoginRequired
	}
	return u, nil
}

func (s *Service) issueAccessToken(u users.User, client Client, scope string) (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(s.accessTTL)
	claims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       u.ID.String(),
		"uid":       u.ID.String(),
		"username":  u.Username,
		"email":     u.Email,
		"source":    u.Source,
		"client_id": client.ClientID,
		"scope":     scope,
		"iat":       now.Unix(),
		"exp":       expires.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.jwtSecret)
	return signed, expires, err
}

func normalizeScope(scope string) string { return strings.Join(strings.Fields(scope), " ") }

func scopeAllowed(requested string, allowed []string) bool {
	for _, s := range strings.Fields(requested) {
		if !slices.Contains(allowed, s) {
			return false
		}
	}
	return true
}

func generateClientSecret() (string, error) {
	raw, _, err := NewAuthorizationCode()
	return raw, err
}

func IsNotFound(err error) bool { return errors.Is(err, storage.ErrNotFound) }
