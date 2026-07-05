package auth

import (
	"context"
	"errors"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type LDAPAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (users.User, error)
}

// MFAVerifier checks a TOTP or recovery code (implemented by account.Service).
type MFAVerifier interface {
	VerifyCode(ctx context.Context, u users.User, code string) (bool, error)
}

// MFATokenIssuer bridges the two steps of a two-factor login.
type MFATokenIssuer interface {
	IssueMFAToken(u users.User) (string, error)
	VerifyMFAToken(token string) (string, error)
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
	mfa        MFAVerifier
	mfaTokens  MFATokenIssuer
}

func NewService(users users.Repository, sessions SessionRepository, audit audit.Repository, passwords PasswordHasher, tokens JWTIssuer, sessionTTL time.Duration) *Service {
	return &Service{users: users, sessions: sessions, audit: audit, passwords: passwords, tokens: tokens, sessionTTL: sessionTTL}
}
func (s *Service) WithLDAP(a LDAPAuthenticator) *Service         { s.ldap = a; return s }
func (s *Service) WithLockout(r LoginAttemptRepository) *Service { s.attempts = r; return s }
func (s *Service) WithMFA(v MFAVerifier, t MFATokenIssuer) *Service {
	s.mfa = v
	s.mfaTokens = t
	return s
}

type LoginInput struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}
type LoginResult struct {
	User                 users.User `json:"user"`
	AccessToken          string     `json:"access_token,omitempty"`
	AccessTokenExpiresAt time.Time  `json:"access_token_expires_at"`
	SessionToken         string     `json:"session_token,omitempty"`
	SessionExpiresAt     time.Time  `json:"session_expires_at"`
	MFARequired          bool       `json:"mfa_required,omitempty"`
	MFAToken             string     `json:"mfa_token,omitempty"`
}

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrUserBlocked = errors.New("user is not active")
var ErrInvalidMFACode = errors.New("invalid mfa code")

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
	if u.MFAEnabled && s.mfaTokens != nil {
		t, err := s.mfaTokens.IssueMFAToken(u)
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{MFARequired: true, MFAToken: t}, nil
	}
	return s.establishSession(ctx, u, in)
}

// CompleteMFALogin exchanges a pending mfa_token plus a valid TOTP/recovery
// code for a real session. Wrong codes count toward the brute-force lockout.
func (s *Service) CompleteMFALogin(ctx context.Context, mfaToken, code string, in LoginInput) (LoginResult, error) {
	if s.mfaTokens == nil || s.mfa == nil {
		return LoginResult{}, errors.New("mfa is not configured")
	}
	userIDStr, err := s.mfaTokens.VerifyMFAToken(mfaToken)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	u, err := s.users.FindByID(ctx, userID)
	if err != nil || !u.MFAEnabled || u.Status != users.StatusActive {
		return LoginResult{}, ErrInvalidCredentials
	}
	in.Username = u.Username
	if err := s.checkLockout(ctx, in); err != nil {
		return LoginResult{}, err
	}
	ok, err := s.mfa.VerifyCode(ctx, u, code)
	if err != nil || !ok {
		_ = s.registerFailure(ctx, in)
		return LoginResult{}, ErrInvalidMFACode
	}
	return s.establishSession(ctx, u, in)
}

func (s *Service) establishSession(ctx context.Context, u users.User, in LoginInput) (LoginResult, error) {
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
