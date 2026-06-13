package bootstrap

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/users"
	"strings"
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

type Status struct {
	Initialized bool `json:"initialized"`
}
type CreateAdminInput struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var ErrAlreadyInitialized = errors.New("system already initialized")

func (s *Service) Status(ctx context.Context) (Status, error) {
	c, err := s.users.Count(ctx)
	return Status{Initialized: c > 0}, err
}
func (s *Service) CreateAdmin(ctx context.Context, in CreateAdminInput, ip, ua string) (users.User, error) {
	st, err := s.Status(ctx)
	if err != nil {
		return users.User{}, err
	}
	if st.Initialized {
		return users.User{}, ErrAlreadyInitialized
	}
	if strings.TrimSpace(in.Username) == "" || strings.TrimSpace(in.Email) == "" || len(in.Password) < 12 {
		return users.User{}, errors.New("username, email and password>=12 are required")
	}
	h, err := s.passwords.Hash(in.Password)
	if err != nil {
		return users.User{}, err
	}
	u, err := s.users.Create(ctx, users.User{Username: in.Username, Email: in.Email, PasswordHash: &h, Status: users.StatusActive, Source: users.SourceLocal})
	if err != nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "bootstrap_failed", TargetType: "user", TargetID: in.Username, IP: ip, UserAgent: ua})
		return users.User{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "bootstrap_completed", TargetType: "user", TargetID: u.ID.String(), IP: ip, UserAgent: ua})
	return u, nil
}
