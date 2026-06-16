package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/rbac"
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

func (f *fakeUsersRepo) Create(ctx context.Context, u users.User) (users.User, error) {
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
func (f *fakeUsersRepo) UpsertLDAP(ctx context.Context, u users.User) (users.User, error) {
	return users.User{}, storage.ErrNotFound
}
func (f *fakeUsersRepo) FindByID(ctx context.Context, id uuid.UUID) (users.User, error) {
	for _, u := range f.items {
		if u.ID == id {
			return u, nil
		}
	}
	return users.User{}, storage.ErrNotFound
}
func (f *fakeUsersRepo) FindByUsername(ctx context.Context, username string) (users.User, error) {
	for _, u := range f.items {
		if u.Username == username {
			return u, nil
		}
	}
	return users.User{}, storage.ErrNotFound
}
func (f *fakeUsersRepo) List(context.Context, int, int) ([]users.User, error)         { return f.items, nil }
func (f *fakeUsersRepo) Update(ctx context.Context, u users.User) (users.User, error) { return u, nil }
func (f *fakeUsersRepo) SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	return nil
}
func (f *fakeUsersRepo) TouchLastLogin(ctx context.Context, id uuid.UUID) error { return nil }
func (f *fakeUsersRepo) Count(ctx context.Context) (int64, error)               { return int64(len(f.items)), nil }

type fakeRBAC struct {
	role        rbac.Role
	assigned    bool
	missingRole bool
}

func (f *fakeRBAC) ListRoles(context.Context) ([]rbac.Role, error) { return []rbac.Role{f.role}, nil }
func (f *fakeRBAC) CreateRole(_ context.Context, role rbac.Role) (rbac.Role, error) {
	return role, nil
}
func (f *fakeRBAC) FindRoleByCode(_ context.Context, code string) (rbac.Role, error) {
	if f.missingRole || code != "admin" {
		return rbac.Role{}, storage.ErrNotFound
	}
	if f.role.ID == uuid.Nil {
		f.role = rbac.Role{ID: uuid.New(), Code: "admin", Name: "Administrator"}
	}
	return f.role, nil
}
func (f *fakeRBAC) ListPermissions(context.Context) ([]rbac.Permission, error) { return nil, nil }
func (f *fakeRBAC) ListUserRoles(context.Context, uuid.UUID) ([]rbac.Role, error) {
	return nil, nil
}
func (f *fakeRBAC) ListRolePermissions(context.Context, uuid.UUID) ([]rbac.Permission, error) {
	return nil, nil
}
func (f *fakeRBAC) AssignRoleToUser(context.Context, uuid.UUID, uuid.UUID) error {
	f.assigned = true
	return nil
}
func (f *fakeRBAC) RemoveRoleFromUser(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeRBAC) AssignPermissionToRole(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (f *fakeRBAC) RemovePermissionFromRole(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (f *fakeRBAC) HasPermission(context.Context, uuid.UUID, string, string) (bool, error) {
	return false, nil
}

func TestStatusBeforeBootstrap(t *testing.T) {
	svc := NewService(&fakeUsersRepo{}, fakeHasher{}, &fakeRBAC{missingRole: true}, &fakeAudit{})
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
	rbacRepo := &fakeRBAC{}
	svc := NewService(repo, fakeHasher{}, rbacRepo, auditRepo)
	u, err := svc.CreateAdmin(context.Background(), CreateAdminInput{Username: "admin", Email: "admin@example.com", Password: "StrongPassword123"}, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("CreateAdmin returned error: %v", err)
	}
	if u.Username != "admin" || u.Source != users.SourceLocal || u.Status != users.StatusActive {
		t.Fatalf("unexpected user: %+v", u)
	}
	if !rbacRepo.assigned {
		t.Fatal("expected admin role assignment")
	}
	if len(auditRepo.events) == 0 || auditRepo.events[len(auditRepo.events)-1].Action != "bootstrap_completed" {
		t.Fatalf("expected bootstrap_completed audit event, got %+v", auditRepo.events)
	}
}

func TestCreateAdminAlreadyInitialized(t *testing.T) {
	repo := &fakeUsersRepo{items: []users.User{{ID: uuid.New(), Username: "admin"}}}
	svc := NewService(repo, fakeHasher{}, &fakeRBAC{missingRole: true}, &fakeAudit{})
	_, err := svc.CreateAdmin(context.Background(), CreateAdminInput{Username: "other", Email: "other@example.com", Password: "StrongPassword123"}, "127.0.0.1", "test")
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}
}
