package users

import (
	"context"
	"errors"
	"testing"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type serviceRepository struct {
	Repository
	user        User
	updateCalls int
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
