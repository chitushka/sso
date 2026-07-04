package users

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
	"strings"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
}
type Service struct {
	repo      Repository
	passwords PasswordHasher
	audit     audit.Repository
}

func NewService(repo Repository, passwords PasswordHasher, audit audit.Repository) *Service {
	return &Service{repo: repo, passwords: passwords, audit: audit}
}

type CreateUserInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Status   Status `json:"status"`
}
type UpdateUserInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Status   Status `json:"status"`
}

func (s *Service) Create(ctx context.Context, in CreateUserInput, ip, ua string) (User, error) {
	if strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.Email) == "" || len(in.Password) < 8 {
		return User{}, errors.New("username, email and password>=8 are required")
	}
	if in.Status == "" {
		in.Status = StatusActive
	}
	h, err := s.passwords.Hash(in.Password)
	if err != nil {
		return User{}, err
	}
	u, err := s.repo.Create(ctx, User{Username: in.Username, Email: in.Email, PasswordHash: &h, Status: in.Status, Source: SourceLocal})
	if err != nil {
		return User{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "user_created", TargetType: "user", TargetID: u.ID.String(), IP: ip, UserAgent: ua})
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
	return s.repo.Update(ctx, User{ID: id, Username: in.Username, Email: in.Email, Status: in.Status})
}

// Delete is a soft delete: the row is kept for audit/FK integrity, the status
// blocks login and the user disappears from normal flows.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, ip, ua string) error {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	u.Status = StatusDeleted
	if _, err := s.repo.Update(ctx, u); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "user_deleted", TargetType: "user", TargetID: id.String(), IP: ip, UserAgent: ua})
	return nil
}
func (s *Service) SetPassword(ctx context.Context, id uuid.UUID, password string) error {
	if len(password) < 8 {
		return errors.New("password must contain at least 8 characters")
	}
	h, err := s.passwords.Hash(password)
	if err != nil {
		return err
	}
	return s.repo.SetPasswordHash(ctx, id, h)
}
