package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/storage"
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
func (f *fakeKeyStore) Create(_ context.Context, k SigningKey) (SigningKey, error) {
	k.ID = uuid.New()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	f.keys = append(f.keys, k)
	return k, nil
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
func (f *fakeKeyStore) MarkRetiring(_ context.Context, id uuid.UUID, expiresAt time.Time) error {
	for i := range f.keys {
		if f.keys[i].ID == id {
			f.keys[i].Status = "retiring"
			f.keys[i].ExpiresAt = &expiresAt
		}
	}
	return nil
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
