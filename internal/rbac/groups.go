package rbac

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type Group struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GroupRepository is separate from Repository so existing write-only fakes
// keep compiling.
type GroupRepository interface {
	ListGroups(ctx context.Context) ([]Group, error)
	CreateGroup(ctx context.Context, g Group) (Group, error)
	FindGroupByID(ctx context.Context, id uuid.UUID) (Group, error)
	UpdateGroup(ctx context.Context, g Group) (Group, error)
	DeleteGroup(ctx context.Context, id uuid.UUID) error
	ListGroupRoles(ctx context.Context, groupID uuid.UUID) ([]Role, error)
	AssignRoleToGroup(ctx context.Context, groupID, roleID uuid.UUID) error
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID uuid.UUID) error
	ListUserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error)
	AssignGroupToUser(ctx context.Context, userID, groupID uuid.UUID, source string) error
	RemoveGroupFromUser(ctx context.Context, userID, groupID uuid.UUID) error
	SyncLDAPGroups(ctx context.Context, userID, providerID uuid.UUID, ldapGroups []string) error
}

func (s *Service) WithGroups(gr GroupRepository) *Service { s.groups = gr; return s }

type CreateGroupInput struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}
type UpdateGroupInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Service) ListGroups(ctx context.Context) ([]Group, error) { return s.groups.ListGroups(ctx) }
func (s *Service) CreateGroup(ctx context.Context, in CreateGroupInput) (Group, error) {
	in.Code = strings.TrimSpace(in.Code)
	in.Name = strings.TrimSpace(in.Name)
	if in.Code == "" || in.Name == "" {
		return Group{}, errors.New("group code and name are required")
	}
	g, err := s.groups.CreateGroup(ctx, Group{Code: in.Code, Name: in.Name, Description: in.Description})
	if err != nil {
		return Group{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_created", TargetType: "group", TargetID: g.ID.String()})
	return g, nil
}
func (s *Service) UpdateGroup(ctx context.Context, id uuid.UUID, in UpdateGroupInput) (Group, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return Group{}, errors.New("group name is required")
	}
	g, err := s.groups.UpdateGroup(ctx, Group{ID: id, Name: in.Name, Description: in.Description})
	if err != nil {
		return Group{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_updated", TargetType: "group", TargetID: g.ID.String()})
	return g, nil
}
func (s *Service) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	if err := s.groups.DeleteGroup(ctx, id); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_deleted", TargetType: "group", TargetID: id.String()})
	return nil
}
func (s *Service) ListGroupRoles(ctx context.Context, groupID uuid.UUID) ([]Role, error) {
	return s.groups.ListGroupRoles(ctx, groupID)
}
func (s *Service) AssignRoleToGroup(ctx context.Context, groupID, roleID uuid.UUID) error {
	if err := s.groups.AssignRoleToGroup(ctx, groupID, roleID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_role_assigned", TargetType: "group", TargetID: groupID.String()})
	return nil
}
func (s *Service) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uuid.UUID) error {
	if err := s.groups.RemoveRoleFromGroup(ctx, groupID, roleID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_role_removed", TargetType: "group", TargetID: groupID.String()})
	return nil
}
func (s *Service) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	return s.groups.ListUserGroups(ctx, userID)
}
func (s *Service) AssignGroupToUser(ctx context.Context, userID, groupID uuid.UUID) error {
	if err := s.groups.AssignGroupToUser(ctx, userID, groupID, "manual"); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_assigned", TargetType: "user", TargetID: userID.String()})
	return nil
}
func (s *Service) RemoveGroupFromUser(ctx context.Context, userID, groupID uuid.UUID) error {
	if err := s.groups.RemoveGroupFromUser(ctx, userID, groupID); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "group_removed", TargetType: "user", TargetID: userID.String()})
	return nil
}
