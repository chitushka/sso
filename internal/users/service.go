package users

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/google/uuid"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
}
type ActivationMailer interface {
	Send(ctx context.Context, to, subject, body string) error
}
type PendingCreator interface {
	CreatePending(ctx context.Context, u User, verificationTokenHash string, expiresAt time.Time) (User, error)
}

// TokenCacheInvalidator немедленно удаляет закэшированное состояние доступа.
type TokenCacheInvalidator interface {
	Invalidate(userID uuid.UUID)
}
type Service struct {
	repo       Repository
	pending    PendingCreator
	passwords  PasswordHasher
	audit      audit.Repository
	tokenCache TokenCacheInvalidator
	mail       ActivationMailer
	issuer     string
}

func NewService(repo Repository, passwords PasswordHasher, audit audit.Repository) *Service {
	pending, _ := repo.(PendingCreator)
	return &Service{repo: repo, pending: pending, passwords: passwords, audit: audit}
}
func (s *Service) WithEmailActivation(mail ActivationMailer, issuer string) *Service {
	s.mail = mail
	s.issuer = strings.TrimRight(issuer, "/")
	return s
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
	u, err := s.createLocal(ctx, in, h)
	if err != nil && u.ID == uuid.Nil {
		return User{}, err
	}
	if err := audit.Write(ctx, s.audit, audit.Event{Action: "user_created", TargetType: "user", TargetID: u.ID.String(), IP: ip, UserAgent: ua}); err != nil {
		return User{}, err
	}
	if err != nil {
		return u, err
	}
	return u, nil
}
func (s *Service) createLocal(ctx context.Context, in CreateUserInput, passwordHash string) (User, error) {
	u := User{Username: in.Username, Email: in.Email, PasswordHash: &passwordHash, Status: in.Status, Source: SourceLocal, FirstName: in.FirstName, LastName: in.LastName, Attributes: in.Attributes}
	if in.Status != StatusPending {
		return s.repo.Create(ctx, u)
	}
	return s.createPending(ctx, u)
}

func (s *Service) createPending(ctx context.Context, u User) (User, error) {
	if s.pending == nil || s.mail == nil || s.issuer == "" {
		return User{}, errors.New("email activation is not configured")
	}
	raw, hash, err := newActivationToken()
	if err != nil {
		return User{}, err
	}
	created, err := s.pending.CreatePending(ctx, u, hash, time.Now().Add(24*time.Hour))
	if err != nil {
		return User{}, err
	}
	return created, s.sendActivation(ctx, created, raw)
}

func (s *Service) sendActivation(ctx context.Context, u User, raw string) error {
	link := fmt.Sprintf("%s/verify-email?token=%s", s.issuer, raw)
	body := fmt.Sprintf("Здравствуйте, %s! Подтвердите адрес электронной почты, открыв ссылку в течение 24 часов: %s", u.Username, link)
	return s.mail.Send(ctx, u.Email, "Подтверждение адреса электронной почты", body)
}

func newActivationToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
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
