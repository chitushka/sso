package account

import (
	"context"
	"errors"
	"testing"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
)

type accountCredentials struct {
	CredentialRepository
	userID       uuid.UUID
	resetErr     error
	receivedHash string
}

func (r *accountCredentials) ResetPassword(_ context.Context, _ string, passwordHash string) (uuid.UUID, error) {
	r.receivedHash = passwordHash
	return r.userID, r.resetErr
}

type accountHasher struct{}

func (accountHasher) Hash(password string) (string, error) { return "hash:" + password, nil }
func (accountHasher) Verify(string, string) (bool, error)  { return true, nil }

type accountAudit struct{}

func (accountAudit) Write(context.Context, audit.Event) error { return nil }

type accountCache struct{ invalidated uuid.UUID }

func (c *accountCache) Invalidate(userID uuid.UUID) { c.invalidated = userID }

func TestResetPasswordMapsMissingToken(t *testing.T) {
	repo := &accountCredentials{resetErr: storage.ErrNotFound}
	svc := NewService(nil, repo, nil, accountHasher{}, nil, nil, accountAudit{}, "https://sso.example.org")
	if err := svc.ResetPassword(context.Background(), "expired", "NewPassword123!", "", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("ожидалась ErrInvalidToken, получено: %v", err)
	}
}

func TestResetPasswordInvalidatesAccessCache(t *testing.T) {
	userID := uuid.New()
	repo := &accountCredentials{userID: userID}
	cache := &accountCache{}
	svc := NewService(nil, repo, nil, accountHasher{}, nil, nil, accountAudit{}, "https://sso.example.org").WithTokenCache(cache)
	if err := svc.ResetPassword(context.Background(), "valid", "NewPassword123!", "", ""); err != nil {
		t.Fatal(err)
	}
	if repo.receivedHash != "hash:NewPassword123!" {
		t.Fatalf("неверный хеш пароля: %q", repo.receivedHash)
	}
	if cache.invalidated != userID {
		t.Fatalf("кэш пользователя не очищен: %s", cache.invalidated)
	}
}
