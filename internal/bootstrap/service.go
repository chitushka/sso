package bootstrap

import (
	"context"
	"strings"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/users"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
}

type Service struct {
	users     users.Repository
	passwords PasswordHasher
	audit     audit.Repository
}

func NewService(users users.Repository, passwords PasswordHasher, audit audit.Repository) *Service {
	return &Service{users: users, passwords: passwords, audit: audit}
}

func (s *Service) Status(ctx context.Context) (StatusResponse, error) {
	count, err := s.users.Count(ctx)
	if err != nil {
		return StatusResponse{}, err
	}
	return StatusResponse{Initialized: count > 0}, nil
}

func (s *Service) CreateAdmin(ctx context.Context, in CreateAdminInput, ip, userAgent string) (CreateAdminResponse, error) {
	count, err := s.users.Count(ctx)
	if err != nil {
		return CreateAdminResponse{}, err
	}
	if count > 0 {
		_ = s.audit.Write(ctx, audit.Event{Action: "bootstrap_failed", TargetType: "system", TargetID: "bootstrap", IP: ip, UserAgent: userAgent})
		return CreateAdminResponse{}, ErrAlreadyInitialized
	}

	if strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.Email) == "" || len(in.Password) < 12 {
		_ = s.audit.Write(ctx, audit.Event{Action: "bootstrap_failed", TargetType: "system", TargetID: "bootstrap", IP: ip, UserAgent: userAgent})
		return CreateAdminResponse{}, ErrInvalidInput
	}

	hash, err := s.passwords.Hash(in.Password)
	if err != nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "bootstrap_failed", TargetType: "system", TargetID: "bootstrap", IP: ip, UserAgent: userAgent})
		return CreateAdminResponse{}, err
	}

	admin, err := s.users.Create(ctx, users.User{
		Username:     strings.TrimSpace(in.Username),
		Email:        strings.TrimSpace(in.Email),
		PasswordHash: hash,
		Status:       users.StatusActive,
		Source:       users.SourceLocal,
	})
	if err != nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "bootstrap_failed", TargetType: "system", TargetID: "bootstrap", IP: ip, UserAgent: userAgent})
		return CreateAdminResponse{}, err
	}

	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &admin.ID, Action: "bootstrap_completed", TargetType: "user", TargetID: admin.ID.String(), IP: ip, UserAgent: userAgent})
	return CreateAdminResponse{Initialized: true, User: admin}, nil
}
