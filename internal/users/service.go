package users

import (
	"context"
	"errors"
	"strings"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
}

// TokenCacheInvalidator немедленно удаляет закэшированное состояние доступа.
type TokenCacheInvalidator interface {
	Invalidate(userID uuid.UUID)
}
type Service struct {
	repo       Repository
	passwords  PasswordHasher
	audit      audit.Repository
	tokenCache TokenCacheInvalidator
}

func NewService(repo Repository, passwords PasswordHasher, audit audit.Repository) *Service {
	return &Service{repo: repo, passwords: passwords, audit: audit}
}

// WithTokenCache подключает кэш состояния доступа к операциям смены статуса.
func (s *Service) WithTokenCache(c TokenCacheInvalidator) *Service { s.tokenCache = c; return s }

var ErrDeletedUserRestore = errors.New("deleted user cannot be restored through update")

type CreateUserInput struct {
	Username   string            `json:"username"`
	Email      string            `json:"email"`
	Password   string            `json:"password"`
	Status     Status            `json:"status"`
	FirstName  string            `json:"first_name"`
	LastName   string            `json:"last_name"`
	Attributes map[string]string `json:"attributes"`
}
type UpdateUserInput struct {
	Username   string            `json:"username"`
	Email      string            `json:"email"`
	Status     Status            `json:"status"`
	FirstName  string            `json:"first_name"`
	LastName   string            `json:"last_name"`
	Attributes map[string]string `json:"attributes"`
}

func (s *Service) Create(ctx context.Context, in CreateUserInput, ip, ua string) (User, error) {
	if strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.Email) == "" {
		return User{}, errors.New("username and email are required")
	}
	if err := ValidatePassword(in.Password); err != nil {
		return User{}, err
	}
	if in.Status == "" {
		in.Status = StatusActive
	}
	h, err := s.passwords.Hash(in.Password)
	if err != nil {
		return User{}, err
	}
	u, err := s.repo.Create(ctx, User{Username: in.Username, Email: in.Email, PasswordHash: &h, Status: in.Status, Source: SourceLocal, FirstName: in.FirstName, LastName: in.LastName, Attributes: in.Attributes})
	if err != nil {
		return User{}, err
	}
	if err := audit.Write(ctx, s.audit, audit.Event{Action: "user_created", TargetType: "user", TargetID: u.ID.String(), IP: ip, UserAgent: ua}); err != nil {
		return User{}, err
	}
	return u, nil
}
func (s *Service) List(ctx context.Context, limit, offset int) ([]User, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.List(ctx, limit, offset)
}
func (s *Service) Get(ctx context.Context, id uuid.UUID) (User, error) {
	return s.repo.FindByID(ctx, id)
}
func (s *Service) Update(ctx context.Context, id uuid.UUID, in UpdateUserInput) (User, error) {
	current, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return User{}, err
	}
	if current.Status == StatusDeleted && in.Status != StatusDeleted {
		return User{}, ErrDeletedUserRestore
	}
	u, err := s.repo.Update(ctx, User{ID: id, Username: in.Username, Email: in.Email, Status: in.Status, FirstName: in.FirstName, LastName: in.LastName, Attributes: in.Attributes})
	if err != nil {
		return User{}, err
	}
	if s.tokenCache != nil {
		s.tokenCache.Invalidate(id)
	}
	if err := audit.Write(ctx, s.audit, audit.Event{Action: "user_updated", TargetType: "user", TargetID: id.String()}); err != nil {
		return User{}, err
	}
	return u, nil
}

// Delete выполняет мягкое удаление с атомарным отзывом всех полномочий.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, ip, ua string) error {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	u.Status = StatusDeleted
	if _, err := s.repo.Update(ctx, u); err != nil {
		return err
	}
	if s.tokenCache != nil {
		s.tokenCache.Invalidate(id)
	}
	return audit.Write(ctx, s.audit, audit.Event{Action: "user_deleted", TargetType: "user", TargetID: id.String(), IP: ip, UserAgent: ua})
}
func (s *Service) SetPassword(ctx context.Context, id uuid.UUID, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	h, err := s.passwords.Hash(password)
	if err != nil {
		return err
	}
	return s.repo.SetPasswordHash(ctx, id, h)
}
