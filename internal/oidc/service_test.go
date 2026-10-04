package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type fakeKeyStore struct {
	keys []SigningKey
}

func (f *fakeKeyStore) ActiveKey(_ context.Context) (SigningKey, error) {
	for i := len(f.keys) - 1; i >= 0; i-- {
		if f.keys[i].Status == "active" {
			return f.keys[i], nil
		}
	}
	return SigningKey{}, storage.ErrNotFound
}
func (f *fakeKeyStore) EnsureActive(_ context.Context, k SigningKey) (SigningKey, error) {
	if active, err := f.ActiveKey(context.Background()); err == nil {
		return active, nil
	}
	k.ID = uuid.New()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	f.keys = append(f.keys, k)
	return k, nil
}
func (f *fakeKeyStore) Rotate(_ context.Context, currentID uuid.UUID, k SigningKey, expiresAt time.Time) error {
	for i := range f.keys {
		if f.keys[i].Status == "active" && f.keys[i].ID != currentID {
			return nil
		}
	}
	k.ID = uuid.New()
	k.CreatedAt = time.Now()
	for i := range f.keys {
		if f.keys[i].ID == currentID && f.keys[i].Status == "active" {
			f.keys[i].Status = "retiring"
			f.keys[i].ExpiresAt = &expiresAt
			f.keys = append(f.keys, k)
			return nil
		}
	}
	f.keys = append(f.keys, k)
	return nil
}
func (f *fakeKeyStore) PublicKeys(_ context.Context) ([]SigningKey, error) {
	out := []SigningKey{}
	for _, k := range f.keys {
		if k.Status == "active" || k.Status == "retiring" {
			out = append(out, k)
		}
	}
	return out, nil
}
func (f *fakeKeyStore) RetireExpired(_ context.Context) error {
	now := time.Now()
	for i := range f.keys {
		if f.keys[i].Status == "retiring" && f.keys[i].ExpiresAt != nil && f.keys[i].ExpiresAt.Before(now) {
			f.keys[i].Status = "retired"
		}
	}
	return nil
}

func TestRotateIfNeededCreatesKeyWhenNoneExists(t *testing.T) {
	ks := &fakeKeyStore{}
	svc := NewService("http://localhost:8080", ks)
	if err := svc.RotateIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.ActiveKey(context.Background()); err != nil {
		t.Fatal("expected active key after rotation")
	}
}

func TestRotateIfNeededKeepsFreshKey(t *testing.T) {
	ks := &fakeKeyStore{}
	svc := NewService("http://localhost:8080", ks)
	if err := svc.EnsureActiveKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := ks.ActiveKey(context.Background())
	if err := svc.RotateIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := ks.ActiveKey(context.Background())
	if before.Kid != after.Kid {
		t.Fatal("fresh key must not be rotated")
	}
}

func TestRotateIfNeededRotatesOldKey(t *testing.T) {
	ks := &fakeKeyStore{}
	svc := NewService("http://localhost:8080", ks)
	if err := svc.EnsureActiveKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks.keys[0].CreatedAt = time.Now().Add(-31 * 24 * time.Hour)
	old := ks.keys[0].Kid
	if err := svc.RotateIfNeeded(context.Background()); err != nil {
		t.Fatal(err)
	}
	active, err := ks.ActiveKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if active.Kid == old {
		t.Fatal("expected a new active key")
	}
	pub, _ := ks.PublicKeys(context.Background())
	if len(pub) != 2 {
		t.Fatalf("old key must stay in JWKS while retiring, got %d keys", len(pub))
	}
}

func TestRotateIfNeededKeepsOldKeyActiveWhenGenerationFails(t *testing.T) {
	ks := &fakeKeyStore{}
	svc := NewService("http://localhost:8080", ks)
	if err := svc.EnsureActiveKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	ks.keys[0].CreatedAt = time.Now().Add(-31 * 24 * time.Hour)
	old := ks.keys[0].ID
	svc.newKey = func() (SigningKey, error) { return SigningKey{}, errors.New("entropy unavailable") }
	if err := svc.RotateIfNeeded(context.Background()); err == nil {
		t.Fatal("expected key generation failure")
	}
	active, err := ks.ActiveKey(context.Background())
	if err != nil || active.ID != old {
		t.Fatalf("old key must remain active: key=%+v err=%v", active, err)
	}
}

func TestConcurrentRotationWithStaleCurrentKeyIsNoOp(t *testing.T) {
	ks := &fakeKeyStore{}
	svc := NewService("http://localhost:8080", ks)
	if err := svc.EnsureActiveKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	old, _ := ks.ActiveKey(context.Background())
	first, err := generateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(retireGrace)
	if err := ks.Rotate(context.Background(), old.ID, first, expiresAt); err != nil {
		t.Fatal(err)
	}
	if err := ks.Rotate(context.Background(), old.ID, second, expiresAt); err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, key := range ks.keys {
		if key.Status == "active" {
			active++
		}
	}
	if active != 1 || len(ks.keys) != 2 {
		t.Fatalf("stale rotation created duplicate keys: %+v", ks.keys)
	}
}

func TestAccessTokensUseRotatingRSAKeysAndStrictClaims(t *testing.T) {
	ctx := context.Background()
	ks := &fakeKeyStore{}
	svc := NewService("https://sso.example.com/", ks).WithAccessTokenTTL(15 * time.Minute)
	if err := svc.EnsureActiveKey(ctx); err != nil {
		t.Fatal(err)
	}
	u := users.User{ID: uuid.New(), Username: "alice", Email: "alice@example.com", Source: users.SourceLocal}

	adminToken, _, err := svc.Issue(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(adminToken, &auth.Claims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Method.Alg() != "RS256" || parsed.Header["kid"] == "" || parsed.Header["typ"] != "at+jwt" {
		t.Fatalf("unexpected protected header: %#v", parsed.Header)
	}
	adminClaims, err := svc.VerifyAdminAccessToken(ctx, adminToken)
	if err != nil {
		t.Fatalf("verify admin token: %v", err)
	}
	if adminClaims.Issuer != "https://sso.example.com" || adminClaims.TokenType != auth.TokenTypeAdminAccess || adminClaims.UserID != u.ID.String() {
		t.Fatalf("unexpected admin claims: %+v", adminClaims)
	}
	if _, err := svc.VerifyOAuthAccessToken(ctx, adminToken, "web-app"); err == nil {
		t.Fatal("admin token must not be accepted by an OAuth resource server")
	}

	oauthToken, _, err := svc.IssueOAuthAccessToken(ctx, u, "web-app", "openid profile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyOAuthAccessToken(ctx, oauthToken, "other-app"); err == nil {
		t.Fatal("OAuth token must be rejected for a different audience")
	}
	oauthClaims, err := svc.VerifyOAuthAccessToken(ctx, oauthToken, "web-app")
	if err != nil {
		t.Fatalf("verify OAuth token: %v", err)
	}
	if oauthClaims.TokenType != auth.TokenTypeOAuthAccess || oauthClaims.ClientID != "web-app" {
		t.Fatalf("unexpected OAuth claims: %+v", oauthClaims)
	}
	if _, err := svc.VerifyAdminAccessToken(ctx, oauthToken); err == nil {
		t.Fatal("OAuth token must not be accepted by the admin API")
	}
	foreignIssuer := NewService("https://other-issuer.example.com", ks)
	foreignToken, _, err := foreignIssuer.IssueOAuthAccessToken(ctx, u, "web-app", "openid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyOAuthAccessToken(ctx, foreignToken, "web-app"); err == nil {
		t.Fatal("OAuth token from a different issuer must be rejected")
	}

	ks.keys[0].CreatedAt = time.Now().Add(-31 * 24 * time.Hour)
	if err := svc.RotateIfNeeded(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyOAuthAccessToken(ctx, oauthToken, "web-app"); err != nil {
		t.Fatalf("token signed by a retiring key must remain valid: %v", err)
	}
}
