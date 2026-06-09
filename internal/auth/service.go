package auth

import (
	"context"
	"errors"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
)

type Service struct {
	users      users.Repository
	sessions   SessionRepository
	audit      audit.Repository
	passwords  PasswordHasher
	tokens     JWTIssuer
	sessionTTL time.Duration
}

func NewService(users users.Repository, sessions SessionRepository, audit audit.Repository, passwords PasswordHasher, tokens JWTIssuer, sessionTTL time.Duration) *Service {
	return &Service{users: users, sessions: sessions, audit: audit, passwords: passwords, tokens: tokens, sessionTTL: sessionTTL}
}

type LoginInput struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}
type LoginResult struct {
	User                 users.User `json:"user"`
	AccessToken          string     `json:"access_token"`
	AccessTokenExpiresAt time.Time  `json:"access_token_expires_at"`
	SessionToken         string     `json:"session_token"`
	SessionExpiresAt     time.Time  `json:"session_expires_at"`
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrUserBlocked = errors.New("user is not active")

func (s *Service) Login(ctx context.Context, in LoginInput) (LoginResult, error) {
	u, err := s.users.FindByUsername(ctx, in.Username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return LoginResult{}, ErrInvalidCredentials
		}
		return LoginResult{}, err
	}
	if u.Status != users.StatusActive {
		return LoginResult{}, ErrUserBlocked
	}
	ok, err := s.passwords.Verify(in.Password, u.PasswordHash)
	if err != nil || !ok {
		_ = s.audit.Write(ctx, audit.Event{Action: "login_failed", TargetType: "user", TargetID: in.Username, IP: in.IP, UserAgent: in.UserAgent})
		return LoginResult{}, ErrInvalidCredentials
	}
	access, accessExp, err := s.tokens.Issue(u)
	if err != nil {
		return LoginResult{}, err
	}
	sessionRaw, sessionHash, err := NewSessionToken()
	if err != nil {
		return LoginResult{}, err
	}
	sessionExp := time.Now().Add(s.sessionTTL)
	_, err = s.sessions.Create(ctx, Session{UserID: u.ID, TokenHash: sessionHash, IP: in.IP, UserAgent: in.UserAgent, ExpiresAt: sessionExp})
	if err != nil {
		return LoginResult{}, err
	}
	_ = s.users.TouchLastLogin(ctx, u.ID)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "login_success", TargetType: "user", TargetID: u.ID.String(), IP: in.IP, UserAgent: in.UserAgent})
	return LoginResult{User: u, AccessToken: access, AccessTokenExpiresAt: accessExp, SessionToken: sessionRaw, SessionExpiresAt: sessionExp}, nil
}
func (s *Service) Logout(ctx context.Context, rawSessionToken string) error {
	if rawSessionToken == "" {
		return nil
	}
	return s.sessions.RevokeByTokenHash(ctx, HashSessionToken(rawSessionToken))
}
