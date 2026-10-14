package users

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type serviceRepository struct {
	Repository
	user        User
	updateCalls int
	pendingHash string
}

func (r *serviceRepository) CreatePending(_ context.Context, u User, hash string, _ time.Time) (User, error) {
	r.pendingHash = hash
	u.ID = uuid.New()
	r.user = u
	return u, nil
}

type serviceHasher struct{}

func (serviceHasher) Hash(string) (string, error) { return "hash", nil }

type serviceMailer struct{ body string }

func (m *serviceMailer) Send(_ context.Context, _, _, body string) error {
	m.body = body
	return nil
}

func (r *serviceRepository) FindByID(_ context.Context, _ uuid.UUID) (User, error) {
	return r.user, nil
}

func (r *serviceRepository) Update(_ context.Context, u User) (User, error) {
	r.updateCalls++
	r.user = u
	return u, nil
}

type serviceAudit struct{}

func (serviceAudit) Write(context.Context, audit.Event) error { return nil }

type cacheInvalidator struct {
	userID uuid.UUID
}

func (c *cacheInvalidator) Invalidate(userID uuid.UUID) { c.userID = userID }

func TestCreatePendingIssuesActivationTokenAndSendsEmail(t *testing.T) {
	repo := &serviceRepository{}
	mail := &serviceMailer{}
	svc := NewService(repo, serviceHasher{}, serviceAudit{}).WithEmailActivation(mail, "https://sso.example.org/")
	u, err := svc.Create(context.Background(), CreateUserInput{Username: "pending", Email: "user@example.org", Password: "long-enough-password", Status: StatusPending}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != StatusPending || repo.pendingHash == "" {
		t.Fatalf("pending-пользователь или токен не сохранены: %+v", u)
	}
	const marker = "token="
	pos := strings.LastIndex(mail.body, marker)
	if pos < 0 {
		t.Fatalf("письмо не содержит ссылку активации: %q", mail.body)
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(mail.body[pos+len(marker):])))
	if hex.EncodeToString(sum[:]) != repo.pendingHash {
		t.Fatal("в письме передан токен, не соответствующий сохранённому хешу")
	}
}

func TestUpdateInvalidatesAccessStateCache(t *testing.T) {
	userID := uuid.New()
	repo := &serviceRepository{user: User{ID: userID, Username: "user", Email: "user@example.org", Status: StatusActive}}
	cache := &cacheInvalidator{}
	svc := NewService(repo, nil, serviceAudit{}).WithTokenCache(cache)

	_, err := svc.Update(context.Background(), userID, UpdateUserInput{Username: "user", Email: "user@example.org", Status: StatusBlocked})
	if err != nil {
		t.Fatal(err)
	}
	if cache.userID != userID {
		t.Fatalf("кэш состояния доступа не очищен: %s", cache.userID)
	}
}

func TestUpdateCannotRestoreDeletedUser(t *testing.T) {
	userID := uuid.New()
	repo := &serviceRepository{user: User{ID: userID, Username: "user", Email: "user@example.org", Status: StatusDeleted}}
	svc := NewService(repo, nil, serviceAudit{})

	_, err := svc.Update(context.Background(), userID, UpdateUserInput{Username: "user", Email: "user@example.org", Status: StatusActive})
	if !errors.Is(err, ErrDeletedUserRestore) {
		t.Fatalf("ожидалась ErrDeletedUserRestore, получено: %v", err)
	}
	if repo.updateCalls != 0 {
		t.Fatalf("репозиторий вызван для восстановления удалённого пользователя: %d", repo.updateCalls)
	}
}
