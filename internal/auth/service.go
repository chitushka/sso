package auth

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"time"
)

type LDAPAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (users.User, error)
}
type Service struct {
	users      users.Repository
	sessions   SessionRepository
	audit      audit.Repository
	passwords  PasswordHasher
	tokens     JWTIssuer
	sessionTTL time.Duration
	ldap       LDAPAuthenticator
	attempts   LoginAttemptRepository
}

func NewService(users users.Repository, sessions SessionRepository, audit audit.Repository, passwords PasswordHasher, tokens JWTIssuer, sessionTTL time.Duration) *Service {
	return &Service{users: users, sessions: sessions, audit: audit, passwords: passwords, tokens: tokens, sessionTTL: sessionTTL}
}
func (s *Service) WithLDAP(a LDAPAuthenticator) *Service         { s.ldap = a; return s }
func (s *Service) WithLockout(r LoginAttemptRepository) *Service { s.attempts = r; return s }

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
	if err := s.checkLockout(ctx, in); err != nil {
		return LoginResult{}, err
	}
	u, err := s.users.FindByUsername(ctx, in.Username)
	if err == nil && u.Source == users.SourceLocal {
		if u.Status != users.StatusActive {
			return LoginResult{}, ErrUserBlocked
		}
		if u.PasswordHash == nil {
			return LoginResult{}, ErrInvalidCredentials
		}
		ok, verr := s.passwords.Verify(in.Password, *u.PasswordHash)
		if verr != nil || !ok {
			return LoginResult{}, s.registerFailure(ctx, in)
		}
		return s.finishLogin(ctx, u, in)
	}
	if s.ldap != nil {
		lu, lerr := s.ldap.Authenticate(ctx, in.Username, in.Password)
		if lerr == nil {
			return s.finishLogin(ctx, lu, in)
		}
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return LoginResult{}, err
	}
	return LoginResult{}, s.registerFailure(ctx, in)
}
func (s *Service) checkLockout(ctx context.Context, in LoginInput) error {
	if s.attempts == nil {
		return nil
	}
	st, err := s.attempts.Status(ctx, in.Username, in.IP)
	if err != nil {
		return err
	}
	if st.LockedUntil != nil && time.Now().Before(*st.LockedUntil) {
		return ErrLoginLocked
	}
	return nil
}
func (s *Service) registerFailure(ctx context.Context, in LoginInput) error {
	_ = s.audit.Write(ctx, audit.Event{Action: "login_failed", TargetType: "user", TargetID: in.Username, IP: in.IP, UserAgent: in.UserAgent})
	if s.attempts == nil {
		return ErrInvalidCredentials
	}
	n, err := s.attempts.Fail(ctx, in.Username, in.IP)
	if err != nil {
		return ErrInvalidCredentials
	}
	if n >= maxAttempts {
		until := time.Now().Add(lockDuration(n))
		if err := s.attempts.Lock(ctx, in.Username, in.IP, until); err == nil {
			_ = s.audit.Write(ctx, audit.Event{Action: "login_locked", TargetType: "user", TargetID: in.Username, IP: in.IP, UserAgent: in.UserAgent})
		}
	}
	return ErrInvalidCredentials
}
func (s *Service) finishLogin(ctx context.Context, u users.User, in LoginInput) (LoginResult, error) {
	access, accessExp, err := s.tokens.Issue(u)
	if err != nil {
		return LoginResult{}, err
	}
	raw, hash, err := NewSessionToken()
	if err != nil {
		return LoginResult{}, err
	}
	exp := time.Now().Add(s.sessionTTL)
	if _, err = s.sessions.Create(ctx, Session{UserID: u.ID, TokenHash: hash, IP: in.IP, UserAgent: in.UserAgent, ExpiresAt: exp}); err != nil {
		return LoginResult{}, err
	}
	_ = s.users.TouchLastLogin(ctx, u.ID)
	if s.attempts != nil {
		_ = s.attempts.Reset(ctx, in.Username, in.IP)
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "login_success", TargetType: "user", TargetID: u.ID.String(), IP: in.IP, UserAgent: in.UserAgent})
	return LoginResult{User: u, AccessToken: access, AccessTokenExpiresAt: accessExp, SessionToken: raw, SessionExpiresAt: exp}, nil
}
func (s *Service) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	return s.sessions.RevokeByTokenHash(ctx, HashSessionToken(raw))
}
