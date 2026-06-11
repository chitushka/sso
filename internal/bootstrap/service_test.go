package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type fakeHasher struct{}

func (fakeHasher) Hash(password string) (string, error) { return "hash:" + password, nil }

type fakeAudit struct{ events []audit.Event }

func (f *fakeAudit) Write(_ context.Context, e audit.Event) error {
	f.events = append(f.events, e)
	return nil
}

type fakeUsersRepo struct {
	items []users.User
}

func (f *fakeUsersRepo) Create(_ context.Context, u users.User) (users.User, error) {
	for _, existing := range f.items {
		if existing.Username == u.Username {
			return users.User{}, storage.ErrConflict
		}
	}
	now := time.Now()
	u.ID = uuid.New()
	u.CreatedAt = now
	u.UpdatedAt = now
	f.items = append(f.items, u)
	return u, nil
}
func (f *fakeUsersRepo) FindByID(_ context.Context, id uuid.UUID) (users.User, error) {
	for _, u := range f.items {
		if u.ID == id {
			return u, nil
		}
	}
	return users.User{}, storage.ErrNotFound
}
func (f *fakeUsersRepo) FindByUsername(_ context.Context, username string) (users.User, error) {
	for _, u := range f.items {
		if u.Username == username {
			return u, nil
		}
	}
	return users.User{}, storage.ErrNotFound
}
func (f *fakeUsersRepo) FindByLDAPDN(context.Context, uuid.UUID, string) (users.User, error) {
	return users.User{}, storage.ErrNotFound
}
func (f *fakeUsersRepo) List(context.Context, int, int) ([]users.User, error)       { return f.items, nil }
func (f *fakeUsersRepo) Update(_ context.Context, u users.User) (users.User, error) { return u, nil }
func (f *fakeUsersRepo) SetPasswordHash(context.Context, uuid.UUID, string) error   { return nil }
func (f *fakeUsersRepo) SyncLDAPUser(_ context.Context, u users.User) (users.User, error) {
	return f.Create(context.Background(), u)
}
func (f *fakeUsersRepo) TouchLastLogin(context.Context, uuid.UUID) error { return nil }
func (f *fakeUsersRepo) Count(context.Context) (int64, error)            { return int64(len(f.items)), nil }

func TestStatusBeforeBootstrap(t *testing.T) {
	svc := NewService(&fakeUsersRepo{}, fakeHasher{}, &fakeAudit{})
	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.Initialized {
		t.Fatal("expected initialized=false")
	}
}

func TestCreateAdmin(t *testing.T) {
	repo := &fakeUsersRepo{}
	auditRepo := &fakeAudit{}
	svc := NewService(repo, fakeHasher{}, auditRepo)
	res, err := svc.CreateAdmin(context.Background(), CreateAdminInput{Username: "admin", Email: "admin@example.com", Password: "StrongPassword123"}, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("CreateAdmin returned error: %v", err)
	}
	if !res.Initialized {
		t.Fatal("expected initialized=true")
	}
	if res.User.Username != "admin" || res.User.Source != users.SourceLocal || res.User.Status != users.StatusActive {
		t.Fatalf("unexpected user: %+v", res.User)
	}
	if len(auditRepo.events) == 0 || auditRepo.events[len(auditRepo.events)-1].Action != "bootstrap_completed" {
		t.Fatalf("expected bootstrap_completed audit event, got %+v", auditRepo.events)
	}
}

func TestCreateAdminAlreadyInitialized(t *testing.T) {
	repo := &fakeUsersRepo{items: []users.User{{ID: uuid.New(), Username: "admin"}}}
	svc := NewService(repo, fakeHasher{}, &fakeAudit{})
	_, err := svc.CreateAdmin(context.Background(), CreateAdminInput{Username: "other", Email: "other@example.com", Password: "StrongPassword123"}, "127.0.0.1", "test")
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}
}
