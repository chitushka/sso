package rbac

import (
	"context"
	"errors"
	"strings"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type Service struct {
	repo  Repository
	audit audit.Repository
}

func NewService(repo Repository, audit audit.Repository) *Service {
	return &Service{repo: repo, audit: audit}
}

func (s *Service) ListRoles(ctx context.Context) ([]Role, error) { return s.repo.ListRoles(ctx) }
func (s *Service) ListPermissions(ctx context.Context) ([]Permission, error) {
	return s.repo.ListPermissions(ctx)
}
func (s *Service) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]Role, error) {
	return s.repo.ListUserRoles(ctx, userID)
}
func (s *Service) ListRolePermissions(ctx context.Context, roleID uuid.UUID) ([]Permission, error) {
	return s.repo.ListRolePermissions(ctx, roleID)
}

func (s *Service) CreateRole(ctx context.Context, in CreateRoleInput) (Role, error) {
	in.Code = strings.TrimSpace(in.Code)
	in.Name = strings.TrimSpace(in.Name)
	if in.Code == "" || in.Name == "" {
		return Role{}, errors.New("role code and name are required")
	}
	role, err := s.repo.CreateRole(ctx, Role{Code: in.Code, Name: in.Name, Description: in.Description})
	if err != nil {
		return Role{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "role_created", TargetType: "role", TargetID: role.ID.String()})
	return role, nil
}

var ErrBuiltInRole = errors.New("built-in roles cannot be deleted")

type UpdateRoleInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Service) UpdateRole(ctx context.Context, id uuid.UUID, in UpdateRoleInput) (Role, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return Role{}, errors.New("role name is required")
	}
	role, err := s.repo.UpdateRole(ctx, Role{ID: id, Name: in.Name, Description: in.Description})
	if err != nil {
		return Role{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "role_updated", TargetType: "role", TargetID: role.ID.String()})
	return role, nil
}

func (s *Service) DeleteRole(ctx context.Context, id uuid.UUID) error {
	role, err := s.repo.FindRoleByID(ctx, id)
	if err != nil {
		return err
	}
	if role.Code == "admin" || role.Code == "user" {
		return ErrBuiltInRole
	}
	if err := s.repo.DeleteRole(ctx, id); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "role_deleted", TargetType: "role", TargetID: id.String()})
	return nil
}

func (s *Service) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	if err := s.repo.AssignRoleToUser(ctx, userID, roleID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "role_assigned", TargetType: "user", TargetID: userID.String()})
	return nil
}

func (s *Service) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	if err := s.repo.RemoveRoleFromUser(ctx, userID, roleID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "role_removed", TargetType: "user", TargetID: userID.String()})
	return nil
}

func (s *Service) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	if err := s.repo.AssignPermissionToRole(ctx, roleID, permissionID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "permission_assigned", TargetType: "role", TargetID: roleID.String()})
	return nil
}

func (s *Service) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	if err := s.repo.RemovePermissionFromRole(ctx, roleID, permissionID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "permission_removed", TargetType: "role", TargetID: roleID.String()})
	return nil
}
