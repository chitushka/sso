package rbac

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	ListRoles(ctx context.Context) ([]Role, error)
	CreateRole(ctx context.Context, role Role) (Role, error)
	FindRoleByCode(ctx context.Context, code string) (Role, error)
	ListPermissions(ctx context.Context) ([]Permission, error)
	ListUserRoles(ctx context.Context, userID uuid.UUID) ([]Role, error)
	ListRolePermissions(ctx context.Context, roleID uuid.UUID) ([]Permission, error)
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error)
}
