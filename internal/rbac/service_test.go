package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type roleRepository struct {
	Repository
	role        Role
	createCalls int
	deleteCalls int
}

func (r *roleRepository) CreateRole(_ context.Context, role Role) (Role, error) {
	r.createCalls++
	role.ID = uuid.New()
	r.role = role
	return role, nil
}

func (r *roleRepository) FindRoleByID(context.Context, uuid.UUID) (Role, error) {
	return r.role, nil
}

func (r *roleRepository) DeleteRole(context.Context, uuid.UUID) error {
	r.deleteCalls++
	return nil
}

type roleAudit struct{}

func (roleAudit) Write(context.Context, audit.Event) error { return nil }

func TestCreateRoleNormalizesRequiredFields(t *testing.T) {
	repo := &roleRepository{}
	svc := NewService(repo, roleAudit{})
	role, err := svc.CreateRole(context.Background(), CreateRoleInput{Code: " support ", Name: " Support "})
	if err != nil {
		t.Fatal(err)
	}
	if role.Code != "support" || role.Name != "Support" || repo.createCalls != 1 {
		t.Fatalf("роль нормализована неверно: %+v calls=%d", role, repo.createCalls)
	}
}

func TestDeleteBuiltInRoleIsForbidden(t *testing.T) {
	repo := &roleRepository{role: Role{ID: uuid.New(), Code: "admin", Name: "Admin"}}
	svc := NewService(repo, roleAudit{})
	if err := svc.DeleteRole(context.Background(), repo.role.ID); !errors.Is(err, ErrBuiltInRole) {
		t.Fatalf("ожидалась ErrBuiltInRole, получено: %v", err)
	}
	if repo.deleteCalls != 0 {
		t.Fatalf("встроенная роль передана на удаление: %d", repo.deleteCalls)
	}
}
