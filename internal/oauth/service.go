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

// IDTokenVerifier validates an id_token_hint and returns its subject and audience.
type IDTokenVerifier interface {
	VerifyIDToken(ctx context.Context, raw string) (sub, clientID string, err error)
}

// BackchannelNotifier delivers an OIDC back-channel logout token to a client.
type BackchannelNotifier interface {
	SendBackchannelLogout(ctx context.Context, sub, clientID, uri string) error
}
type Service struct {
	repo        Repository
	users       users.Repository
	sessions    auth.SessionRepository
	tokens      auth.JWTIssuer
	audit       audit.Repository
	secrets     auth.PasswordHasher
	idTokens    IDTokenIssuer
	verifier    TokenVerifier
	idVerifier  IDTokenVerifier
	backchannel BackchannelNotifier
	refreshTTL  time.Duration
}

var (
	ErrInvalidClient   = errors.New("invalid client credentials")
	ErrInvalidScope    = errors.New("invalid_scope")
	ErrInvalidGrant    = errors.New("invalid_grant")
	ErrConsentRequired = errors.New("consent_required")
	ErrInvalidRedirect = errors.New("invalid post_logout_redirect_uri")
	ErrLoginRequired   = errors.New("login required")
)

func NewService(repo Repository, users users.Repository, sessions auth.SessionRepository, tokens auth.JWTIssuer, audit audit.Repository, secrets auth.PasswordHasher) *Service {
	return &Service{repo: repo, users: users, sessions: sessions, tokens: tokens, audit: audit, secrets: secrets, refreshTTL: 720 * time.Hour}
}
func (s *Service) WithIDTokenIssuer(i IDTokenIssuer) *Service     { s.idTokens = i; return s }
func (s *Service) WithTokenVerifier(v TokenVerifier) *Service     { s.verifier = v; return s }
func (s *Service) WithRefreshTTL(d time.Duration) *Service        { s.refreshTTL = d; return s }
func (s *Service) WithIDTokenVerifier(v IDTokenVerifier) *Service { s.idVerifier = v; return s }
func (s *Service) WithBackchannel(n BackchannelNotifier) *Service { s.backchannel = n; return s }

type CreateClientInput struct {
	ClientID               string     `json:"client_id"`
	Name                   string     `json:"name"`
	Type                   ClientType `json:"type"`
	RedirectURIs           []string   `json:"redirect_uris"`
	AllowedScopes          []string   `json:"allowed_scopes"`
	PostLogoutRedirectURIs []string   `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI   string     `json:"backchannel_logout_uri"`
	SkipConsent            bool       `json:"skip_consent"`
	Enabled                bool       `json:"enabled"`
}
type CreateClientResult struct {
	Client       Client `json:"client"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// nonNil keeps pgx from encoding omitted JSON arrays as NULL into NOT NULL
// TEXT[] columns.
func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func (s *Service) CreateClient(ctx context.Context, in CreateClientInput) (CreateClientResult, error) {
	if in.Type == "" {
		in.Type = ClientConfidential
	}
	c, sec, err := s.repo.CreateClient(ctx, Client{ClientID: in.ClientID, Name: in.Name, Type: in.Type, RedirectURIs: nonNil(in.RedirectURIs), AllowedScopes: nonNil(in.AllowedScopes), PostLogoutRedirectURIs: nonNil(in.PostLogoutRedirectURIs), BackchannelLogoutURI: in.BackchannelLogoutURI, SkipConsent: in.SkipConsent, Enabled: in.Enabled})
	return CreateClientResult{Client: c, ClientSecret: sec}, err
}
func (s *Service) GetClient(ctx context.Context, id uuid.UUID) (Client, error) {
	return s.repo.FindClientByID(ctx, id)
}
func (s *Service) ListClients(ctx context.Context) ([]Client, error) { return s.repo.ListClients(ctx) }

type UpdateClientInput struct {
	Name                   string   `json:"name"`
	RedirectURIs           []string `json:"redirect_uris"`
	AllowedScopes          []string `json:"allowed_scopes"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI   string   `json:"backchannel_logout_uri"`
	SkipConsent            bool     `json:"skip_consent"`
	Enabled                bool     `json:"enabled"`
}

func (s *Service) UpdateClient(ctx context.Context, id uuid.UUID, in UpdateClientInput) (Client, error) {
	c, err := s.repo.UpdateClient(ctx, Client{ID: id, Name: in.Name, RedirectURIs: nonNil(in.RedirectURIs), AllowedScopes: nonNil(in.AllowedScopes), PostLogoutRedirectURIs: nonNil(in.PostLogoutRedirectURIs), BackchannelLogoutURI: in.BackchannelLogoutURI, SkipConsent: in.SkipConsent, Enabled: in.Enabled})
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "oauth_client_updated", TargetType: "oauth_client", TargetID: c.ClientID})
	}
	return c, err
}
func (s *Service) RotateClientSecret(ctx context.Context, id uuid.UUID) (CreateClientResult, error) {
	c, raw, err := s.repo.RotateClientSecret(ctx, id)
	if err != nil {
		return CreateClientResult{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "oauth_client_secret_rotated", TargetType: "oauth_client", TargetID: c.ClientID})
	return CreateClientResult{Client: c, ClientSecret: raw}, nil
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
		return AuthorizeResult{}, ErrLoginRequired
	}
	if !c.SkipConsent {
		granted := ""
		if consent, cerr := s.repo.GetConsent(ctx, sess.UserID, c.ClientID); cerr == nil {
			granted = consent.Scopes
		}
		if !scopeCovered(in.Scope, granted) {
			return AuthorizeResult{}, ErrConsentRequired
		}
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
	GrantType, Code, RedirectURI, ClientID, ClientSecret, CodeVerifier, RefreshToken, Scope string
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
	case "client_credentials":
		return s.clientCredentialsGrant(ctx, in)
	default:
		return TokenResult{}, errors.New("unsupported grant_type")
	}
}

// clientCredentialsGrant issues a service-account token: sub is the client's
// internal id, no refresh or ID token.
func (s *Service) clientCredentialsGrant(ctx context.Context, in TokenInput) (TokenResult, error) {
	c, err := s.authenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return TokenResult{}, err
	}
	if c.Type != ClientConfidential {
		return TokenResult{}, ErrInvalidClient
	}
	if err := validateScope(in.Scope, c.AllowedScopes); err != nil {
		return TokenResult{}, err
	}
	svcAccount := users.User{ID: c.ID, Username: c.ClientID, Source: "client"}
	access, exp, err := s.tokens.IssueOAuthAccessToken(svcAccount, c.ClientID, in.Scope)
	if err != nil {
		return TokenResult{}, err
	}
	return TokenResult{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(time.Until(exp).Seconds()), Scope: in.Scope}, nil
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

type LogoutInput struct{ IDTokenHint, PostLogoutRedirectURI, State, SessionToken string }

// Logout implements RP-initiated logout: revokes the SSO session and the
// user's refresh tokens, notifies the client via back-channel if configured,
// and validates post_logout_redirect_uri against the client's registered list.
func (s *Service) Logout(ctx context.Context, in LogoutInput) (redirect string, err error) {
	var userID *uuid.UUID
	if in.SessionToken != "" {
		hash := auth.HashSessionToken(in.SessionToken)
		if sess, serr := s.sessions.FindByTokenHash(ctx, hash); serr == nil {
			_ = s.sessions.RevokeByTokenHash(ctx, hash)
			userID = &sess.UserID
		}
	}
	var client *Client
	var sub string
	if in.IDTokenHint != "" && s.idVerifier != nil {
		if tokenSub, clientID, verr := s.idVerifier.VerifyIDToken(ctx, in.IDTokenHint); verr == nil {
			sub = tokenSub
			if uid, perr := uuid.Parse(tokenSub); perr == nil && userID == nil {
				userID = &uid
			}
			if c, cerr := s.repo.FindClientByClientID(ctx, clientID); cerr == nil {
				client = &c
			}
		}
	}
	if userID != nil {
		_ = s.repo.RevokeRefreshTokensByUser(ctx, *userID)
		_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, Action: "logout", TargetType: "user", TargetID: userID.String()})
		if sub == "" {
			sub = userID.String()
		}
	}
	if client != nil && client.BackchannelLogoutURI != "" && s.backchannel != nil && sub != "" {
		notifier, uri, clientID := s.backchannel, client.BackchannelLogoutURI, client.ClientID
		go func() {
			nctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = notifier.SendBackchannelLogout(nctx, sub, clientID, uri)
		}()
	}
	if in.PostLogoutRedirectURI == "" {
		return "", nil
	}
	if client == nil || !contains(client.PostLogoutRedirectURIs, in.PostLogoutRedirectURI) {
		return "", ErrInvalidRedirect
	}
	u, perr := url.Parse(in.PostLogoutRedirectURI)
	if perr != nil {
		return "", ErrInvalidRedirect
	}
	if in.State != "" {
		q := u.Query()
		q.Set("state", in.State)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

type ConsentInfo struct {
	ClientID        string   `json:"client_id"`
	ClientName      string   `json:"client_name"`
	RequestedScopes []string `json:"requested_scopes"`
	GrantedScopes   []string `json:"granted_scopes"`
}

func (s *Service) sessionUser(ctx context.Context, sessionToken string) (uuid.UUID, error) {
	sess, err := s.sessions.FindByTokenHash(ctx, auth.HashSessionToken(sessionToken))
	if err != nil || sess.RevokedAt != nil || time.Now().After(sess.ExpiresAt) {
		return uuid.Nil, ErrLoginRequired
	}
	return sess.UserID, nil
}

func (s *Service) GetConsentInfo(ctx context.Context, sessionToken, clientID, scope string) (ConsentInfo, error) {
	userID, err := s.sessionUser(ctx, sessionToken)
	if err != nil {
		return ConsentInfo{}, err
	}
	c, err := s.repo.FindClientByClientID(ctx, clientID)
	if err != nil || !c.Enabled {
		return ConsentInfo{}, ErrInvalidClient
	}
	if err := validateScope(scope, c.AllowedScopes); err != nil {
		return ConsentInfo{}, err
	}
	granted := []string{}
	if consent, cerr := s.repo.GetConsent(ctx, userID, c.ClientID); cerr == nil {
		granted = strings.Fields(consent.Scopes)
	}
	return ConsentInfo{ClientID: c.ClientID, ClientName: c.Name, RequestedScopes: strings.Fields(scope), GrantedScopes: granted}, nil
}

func (s *Service) GrantConsent(ctx context.Context, sessionToken, clientID, scope string) error {
	userID, err := s.sessionUser(ctx, sessionToken)
	if err != nil {
		return err
	}
	c, err := s.repo.FindClientByClientID(ctx, clientID)
	if err != nil || !c.Enabled {
		return ErrInvalidClient
	}
	if err := validateScope(scope, c.AllowedScopes); err != nil {
		return err
	}
	existing := ""
	if consent, cerr := s.repo.GetConsent(ctx, userID, c.ClientID); cerr == nil {
		existing = consent.Scopes
	}
	if err := s.repo.SaveConsent(ctx, UserConsent{UserID: userID, ClientID: c.ClientID, Scopes: mergeScopes(existing, scope)}); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "consent_granted", TargetType: "oauth_client", TargetID: c.ClientID})
	return nil
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

// scopeCovered reports whether every requested scope was already granted.
func scopeCovered(requested, granted string) bool {
	have := strings.Fields(granted)
	for _, sc := range strings.Fields(requested) {
		if !contains(have, sc) {
			return false
		}
	}
	return true
}
func mergeScopes(a, b string) string {
	out := strings.Fields(a)
	for _, sc := range strings.Fields(b) {
		if !contains(out, sc) {
			out = append(out, sc)
		}
	}
	return strings.Join(out, " ")
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
