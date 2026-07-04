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
	clients map[string]Client
	codes   map[string]AuthorizationCode
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{clients: map[string]Client{}, codes: map[string]AuthorizationCode{}}
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
func (f *fakeUsers) TouchLastLogin(_ context.Context, _ uuid.UUID) error            { return nil }
func (f *fakeUsers) Count(_ context.Context) (int64, error)                         { return 1, nil }

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
func (f *fakeSessions) RevokeByTokenHash(_ context.Context, _ string) error { return nil }

type fakeTokens struct{}

func (fakeTokens) Issue(_ users.User) (string, time.Time, error) {
	return "jwt", time.Now().Add(15 * time.Minute), nil
}
func (fakeTokens) IssueOAuthAccessToken(_ users.User, _, _ string) (string, time.Time, error) {
	return "access-token", time.Now().Add(15 * time.Minute), nil
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
	return Client{ClientID: "web-app", ClientSecretHash: strPtr("hash:correct-secret"), Type: ClientConfidential, RedirectURIs: []string{"https://app.example.com/cb"}, AllowedScopes: []string{"openid", "profile", "email"}, Enabled: true}
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
