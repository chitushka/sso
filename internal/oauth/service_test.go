package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type fakeRepo struct {
	clients  map[string]Client
	codes    map[string]AuthorizationCode
	refresh  map[string]RefreshToken
	consents map[string]UserConsent
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{clients: map[string]Client{}, codes: map[string]AuthorizationCode{}, refresh: map[string]RefreshToken{}, consents: map[string]UserConsent{}}
}
func (r *fakeRepo) CreateClient(_ context.Context, c Client) (Client, string, error) {
	r.clients[c.ClientID] = c
	return c, "", nil
}
func (r *fakeRepo) ListClients(_ context.Context) ([]Client, error) { return nil, nil }
func (r *fakeRepo) FindClientByClientID(_ context.Context, clientID string) (Client, error) {
	c, ok := r.clients[clientID]
	if !ok {
		return Client{}, storage.ErrNotFound
	}
	return c, nil
}
func (r *fakeRepo) CreateCode(_ context.Context, c AuthorizationCode) (AuthorizationCode, error) {
	c.CreatedAt = time.Now()
	r.codes[c.CodeHash] = c
	return c, nil
}
func (r *fakeRepo) ConsumeCode(_ context.Context, hash string) (AuthorizationCode, error) {
	c, ok := r.codes[hash]
	if !ok || c.UsedAt != nil || time.Now().After(c.ExpiresAt) {
		return AuthorizationCode{}, storage.ErrNotFound
	}
	now := time.Now()
	c.UsedAt = &now
	r.codes[hash] = c
	return c, nil
}
func (r *fakeRepo) UpdateClient(_ context.Context, c Client) (Client, error) {
	for id, old := range r.clients {
		if old.ID == c.ID {
			c.ClientID = old.ClientID
			r.clients[id] = c
			return c, nil
		}
	}
	return Client{}, storage.ErrNotFound
}
func (r *fakeRepo) RotateClientSecret(_ context.Context, id uuid.UUID) (Client, string, error) {
	for key, c := range r.clients {
		if c.ID == id && c.Type == ClientConfidential {
			h := "hash:rotated-secret"
			c.ClientSecretHash = &h
			r.clients[key] = c
			return c, "rotated-secret", nil
		}
	}
	return Client{}, "", storage.ErrNotFound
}
func (r *fakeRepo) DeleteClient(_ context.Context, id uuid.UUID) error {
	for key, c := range r.clients {
		if c.ID == id {
			delete(r.clients, key)
			return nil
		}
	}
	return storage.ErrNotFound
}
func (r *fakeRepo) CreateRefreshToken(_ context.Context, t RefreshToken) (RefreshToken, error) {
	t.ID = uuid.New()
	t.CreatedAt = time.Now()
	r.refresh[t.TokenHash] = t
	return t, nil
}
func (r *fakeRepo) FindRefreshTokenByHash(_ context.Context, hash string) (RefreshToken, error) {
	t, ok := r.refresh[hash]
	if !ok {
		return RefreshToken{}, storage.ErrNotFound
	}
	return t, nil
}
func (r *fakeRepo) MarkRefreshTokenRotated(_ context.Context, id uuid.UUID) error {
	now := time.Now()
	for hash, t := range r.refresh {
		if t.ID == id {
			if t.RotatedAt != nil {
				return storage.ErrNotFound
			}
			t.RotatedAt = &now
			r.refresh[hash] = t
			return nil
		}
	}
	return storage.ErrNotFound
}
func (r *fakeRepo) RevokeRefreshFamily(_ context.Context, familyID uuid.UUID) error {
	now := time.Now()
	for hash, t := range r.refresh {
		if t.FamilyID == familyID && t.RevokedAt == nil {
			t.RevokedAt = &now
			r.refresh[hash] = t
		}
	}
	return nil
}
func (r *fakeRepo) FindClientByID(_ context.Context, id uuid.UUID) (Client, error) {
	for _, c := range r.clients {
		if c.ID == id {
			return c, nil
		}
	}
	return Client{}, storage.ErrNotFound
}
func (r *fakeRepo) RevokeRefreshTokensByUser(_ context.Context, userID uuid.UUID) error {
	now := time.Now()
	for hash, t := range r.refresh {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
			r.refresh[hash] = t
		}
	}
	return nil
}
func (r *fakeRepo) GetConsent(_ context.Context, userID uuid.UUID, clientID string) (UserConsent, error) {
	c, ok := r.consents[userID.String()+"|"+clientID]
	if !ok {
		return UserConsent{}, storage.ErrNotFound
	}
	return c, nil
}
func (r *fakeRepo) SaveConsent(_ context.Context, c UserConsent) error {
	r.consents[c.UserID.String()+"|"+c.ClientID] = c
	return nil
}

type fakeUsers struct{ u users.User }

func (f *fakeUsers) Create(_ context.Context, u users.User) (users.User, error)     { return u, nil }
func (f *fakeUsers) UpsertLDAP(_ context.Context, u users.User) (users.User, error) { return u, nil }
func (f *fakeUsers) FindByID(_ context.Context, id uuid.UUID) (users.User, error) {
	if id != f.u.ID {
		return users.User{}, storage.ErrNotFound
	}
	return f.u, nil
}
func (f *fakeUsers) FindByUsername(_ context.Context, _ string) (users.User, error) {
	return f.u, nil
}
func (f *fakeUsers) List(_ context.Context, _, _ int) ([]users.User, error)         { return nil, nil }
func (f *fakeUsers) Update(_ context.Context, u users.User) (users.User, error)     { return u, nil }
func (f *fakeUsers) SetPasswordHash(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (f *fakeUsers) SetEmailVerified(_ context.Context, _ uuid.UUID, _ bool) error  { return nil }
func (f *fakeUsers) SetMFA(_ context.Context, _ uuid.UUID, _ bool, _ string) error  { return nil }
func (f *fakeUsers) SetMFACounter(_ context.Context, _ uuid.UUID, _ int64) error    { return nil }
func (f *fakeUsers) FindByEmail(_ context.Context, _ string) (users.User, error)    { return f.u, nil }
func (f *fakeUsers) TouchLastLogin(_ context.Context, _ uuid.UUID) error            { return nil }
func (f *fakeUsers) InvalidateTokens(_ context.Context, _ uuid.UUID) error          { return nil }
func (f *fakeUsers) TokensInvalidBefore(_ context.Context, _ uuid.UUID) (*time.Time, error) {
	return nil, nil
}
func (f *fakeUsers) Count(_ context.Context) (int64, error) { return 1, nil }

type fakeSessions struct{ s auth.Session }

func (f *fakeSessions) Create(_ context.Context, s auth.Session) (auth.Session, error) {
	return s, nil
}
func (f *fakeSessions) FindByTokenHash(_ context.Context, hash string) (auth.Session, error) {
	if hash != f.s.TokenHash {
		return auth.Session{}, storage.ErrNotFound
	}
	return f.s, nil
}
func (f *fakeSessions) RevokeByTokenHash(_ context.Context, _ string) error  { return nil }
func (f *fakeSessions) RevokeAllByUser(_ context.Context, _ uuid.UUID) error { return nil }

type fakeTokens struct{}

func (fakeTokens) Issue(_ users.User) (string, time.Time, error) {
	return "jwt", time.Now().Add(15 * time.Minute), nil
}
func (fakeTokens) IssueOAuthAccessToken(_ users.User, _, _ string) (string, time.Time, error) {
	return "access-token", time.Now().Add(15 * time.Minute), nil
}
func (fakeTokens) IssueClientCredentialsToken(_ users.User, _, _ string) (string, time.Time, error) {
	return "client-token", time.Now().Add(15 * time.Minute), nil
}

type fakeAudit struct{}

func (fakeAudit) Write(_ context.Context, _ audit.Event) error { return nil }

type fakeHasher struct{}

func (fakeHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (fakeHasher) Verify(p, h string) (bool, error) {
	return h == "hash:"+p, nil
}

func setup(t *testing.T, client Client) (*Service, *fakeRepo, users.User, string) {
	t.Helper()
	repo := newFakeRepo()
	repo.clients[client.ClientID] = client
	u := users.User{ID: uuid.New(), Username: "alice", Email: "alice@example.com", Status: users.StatusActive, Source: users.SourceLocal}
	rawSession, sessionHash, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	sessions := &fakeSessions{s: auth.Session{ID: uuid.New(), UserID: u.ID, TokenHash: sessionHash, ExpiresAt: time.Now().Add(time.Hour)}}
	svc := NewService(repo, &fakeUsers{u: u}, sessions, fakeTokens{}, fakeAudit{}, fakeHasher{})
	return svc, repo, u, rawSession
}

func strPtr(s string) *string { return &s }

func confidentialClient() Client {
	return Client{ID: uuid.New(), ClientID: "web-app", ClientSecretHash: strPtr("hash:correct-secret"), Type: ClientConfidential, RedirectURIs: []string{"https://app.example.com/cb"}, AllowedScopes: []string{"openid", "profile", "email"}, PostLogoutRedirectURIs: []string{"https://app.example.com/bye"}, SkipConsent: true, Enabled: true}
}

func authorize(t *testing.T, svc *Service, session, scope string) AuthorizeResult {
	t.Helper()
	res, err := svc.Authorize(context.Background(), AuthorizeInput{ResponseType: "code", ClientID: "web-app", RedirectURI: "https://app.example.com/cb", Scope: scope, SessionToken: session})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return res
}

func TestTokenRejectsMissingClientSecret(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	res := authorize(t, svc, session, "openid")
	_, err := svc.Token(context.Background(), TokenInput{GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example.com/cb", ClientID: "web-app"})
	if !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("want ErrInvalidClient, got %v", err)
	}
}

func TestTokenRejectsWrongClientSecret(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	res := authorize(t, svc, session, "openid")
	_, err := svc.Token(context.Background(), TokenInput{GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example.com/cb", ClientID: "web-app", ClientSecret: "wrong"})
	if !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("want ErrInvalidClient, got %v", err)
	}
}

func TestTokenAcceptsCorrectClientSecret(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	res := authorize(t, svc, session, "profile")
	out, err := svc.Token(context.Background(), TokenInput{GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example.com/cb", ClientID: "web-app", ClientSecret: "correct-secret"})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if out.AccessToken == "" || out.TokenType != "Bearer" {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestAuthorizeRejectsScopeOutsideAllowed(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	_, err := svc.Authorize(context.Background(), AuthorizeInput{ResponseType: "code", ClientID: "web-app", RedirectURI: "https://app.example.com/cb", Scope: "openid admin", SessionToken: session})
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("want ErrInvalidScope, got %v", err)
	}
}

func TestAuthorizeAllowsSubsetScope(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	res := authorize(t, svc, session, "openid email")
	if res.Code == "" {
		t.Fatal("expected code")
	}
}

func TestTokenRejectsCodeReuse(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	res := authorize(t, svc, session, "openid")
	in := TokenInput{GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example.com/cb", ClientID: "web-app", ClientSecret: "correct-secret"}
	if _, err := svc.Token(context.Background(), in); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := svc.Token(context.Background(), in); err == nil {
		t.Fatal("second exchange must fail")
	}
}

func exchangeCode(t *testing.T, svc *Service, session string) TokenResult {
	t.Helper()
	res := authorize(t, svc, session, "profile")
	out, err := svc.Token(context.Background(), TokenInput{GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example.com/cb", ClientID: "web-app", ClientSecret: "correct-secret"})
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	return out
}

func TestTokenIssuesRefreshToken(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	out := exchangeCode(t, svc, session)
	if out.RefreshToken == "" {
		t.Fatal("expected refresh_token in response")
	}
}

func TestRefreshGrantRotatesToken(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	first := exchangeCode(t, svc, session)
	second, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh must return a new rotated token")
	}
	if second.AccessToken == "" {
		t.Fatal("refresh must return an access token")
	}
}

func TestRefreshReuseRevokesFamily(t *testing.T) {
	svc, repo, _, session := setup(t, confidentialClient())
	first := exchangeCode(t, svc, session)
	second, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// Reuse of the already-rotated first token must fail and revoke the family.
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("want ErrInvalidGrant on reuse, got %v", err)
	}
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: second.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("descendant token must be revoked after reuse, got %v", err)
	}
	_ = repo
}

func TestRefreshGrantRejectsWrongClient(t *testing.T) {
	svc, repo, _, session := setup(t, confidentialClient())
	other := Client{ID: uuid.New(), ClientID: "other-app", ClientSecretHash: strPtr("hash:other-secret"), Type: ClientConfidential, RedirectURIs: []string{"https://other.example.com/cb"}, AllowedScopes: []string{"openid"}, Enabled: true}
	repo.clients[other.ClientID] = other
	first := exchangeCode(t, svc, session)
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: "other-app", ClientSecret: "other-secret"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("want ErrInvalidGrant for foreign token, got %v", err)
	}
}

func TestAuthorizeRequiresConsent(t *testing.T) {
	client := confidentialClient()
	client.SkipConsent = false
	svc, _, _, session := setup(t, client)
	_, err := svc.Authorize(context.Background(), AuthorizeInput{ResponseType: "code", ClientID: "web-app", RedirectURI: "https://app.example.com/cb", Scope: "openid profile", SessionToken: session})
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("want ErrConsentRequired, got %v", err)
	}
	if err := svc.GrantConsent(context.Background(), session, "web-app", "openid profile"); err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	res := authorize(t, svc, session, "openid profile")
	if res.Code == "" {
		t.Fatal("expected code after consent")
	}
	// A wider scope than granted must ask again.
	if _, err := svc.Authorize(context.Background(), AuthorizeInput{ResponseType: "code", ClientID: "web-app", RedirectURI: "https://app.example.com/cb", Scope: "openid profile email", SessionToken: session}); !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("wider scope must require consent again, got %v", err)
	}
}

func TestClientCredentialsGrant(t *testing.T) {
	svc, _, _, _ := setup(t, confidentialClient())
	out, err := svc.Token(context.Background(), TokenInput{GrantType: "client_credentials", ClientID: "web-app", ClientSecret: "correct-secret", Scope: "profile"})
	if err != nil {
		t.Fatalf("client_credentials: %v", err)
	}
	if out.AccessToken == "" || out.RefreshToken != "" || out.IDToken != "" {
		t.Fatalf("expected access token only, got %+v", out)
	}
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "client_credentials", ClientID: "web-app", ClientSecret: "wrong", Scope: "profile"}); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("wrong secret must fail, got %v", err)
	}
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "client_credentials", ClientID: "web-app", ClientSecret: "correct-secret", Scope: "admin"}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("scope outside allowed_scopes must fail, got %v", err)
	}
}

type fakeIDVerifier struct{ sub, aud string }

func (f fakeIDVerifier) VerifyIDToken(_ context.Context, raw string) (string, string, error) {
	if raw != "valid-hint" {
		return "", "", errors.New("invalid id token")
	}
	return f.sub, f.aud, nil
}

func TestLogoutRevokesSessionAndTokens(t *testing.T) {
	svc, repo, u, session := setup(t, confidentialClient())
	svc.WithIDTokenVerifier(fakeIDVerifier{sub: u.ID.String(), aud: "web-app"})
	out := exchangeCode(t, svc, session)
	redirect, err := svc.Logout(context.Background(), LogoutInput{SessionToken: session, IDTokenHint: "valid-hint", PostLogoutRedirectURI: "https://app.example.com/bye", State: "xyz"})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if redirect != "https://app.example.com/bye?state=xyz" {
		t.Fatalf("unexpected redirect %q", redirect)
	}
	// Refresh token must be revoked.
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: out.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("refresh after logout must fail, got %v", err)
	}
	_ = repo
}

func TestLogoutRejectsUnregisteredRedirect(t *testing.T) {
	svc, _, u, session := setup(t, confidentialClient())
	svc.WithIDTokenVerifier(fakeIDVerifier{sub: u.ID.String(), aud: "web-app"})
	if _, err := svc.Logout(context.Background(), LogoutInput{SessionToken: session, IDTokenHint: "valid-hint", PostLogoutRedirectURI: "https://evil.example.com/"}); !errors.Is(err, ErrInvalidRedirect) {
		t.Fatalf("want ErrInvalidRedirect, got %v", err)
	}
}

func TestRevokeAndIntrospect(t *testing.T) {
	svc, _, _, session := setup(t, confidentialClient())
	out := exchangeCode(t, svc, session)
	res, err := svc.Introspect(context.Background(), IntrospectInput{Token: out.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"})
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if res["active"] != true {
		t.Fatalf("token must be active, got %v", res)
	}
	if err := svc.Revoke(context.Background(), RevokeInput{Token: out.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	res, err = svc.Introspect(context.Background(), IntrospectInput{Token: out.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"})
	if err != nil {
		t.Fatalf("introspect after revoke: %v", err)
	}
	if res["active"] != false {
		t.Fatalf("token must be inactive after revoke, got %v", res)
	}
	if _, err := svc.Token(context.Background(), TokenInput{GrantType: "refresh_token", RefreshToken: out.RefreshToken, ClientID: "web-app", ClientSecret: "correct-secret"}); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("revoked token must not refresh, got %v", err)
	}
}
