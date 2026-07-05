package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/mailer"
	"github.com/chitushka/sso/internal/mfa"
	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("invalid or expired token")
	ErrInvalidCode  = errors.New("invalid code")
	ErrMFAState     = errors.New("mfa is not in the required state")
)

const (
	resetTTL  = time.Hour
	verifyTTL = 24 * time.Hour
	issuerApp = "SSO"
)

// RefreshRevoker lets the account service kill OAuth refresh tokens on
// password reset without importing the oauth package.
type RefreshRevoker interface {
	RevokeRefreshTokensByUser(ctx context.Context, userID uuid.UUID) error
}

type Service struct {
	users     users.Repository
	tokens    TokenRepository
	recovery  RecoveryCodeRepository
	sessions  auth.SessionRepository
	passwords auth.PasswordHasher
	encryptor secrets.Encryptor
	mail      mailer.Mailer
	audit     audit.Repository
	refresh   RefreshRevoker
	issuer    string
}

func NewService(users users.Repository, tokens TokenRepository, recovery RecoveryCodeRepository, sessions auth.SessionRepository, passwords auth.PasswordHasher, encryptor secrets.Encryptor, mail mailer.Mailer, aud audit.Repository, issuer string) *Service {
	return &Service{users: users, tokens: tokens, recovery: recovery, sessions: sessions, passwords: passwords, encryptor: encryptor, mail: mail, audit: aud, issuer: issuer}
}
func (s *Service) WithRefreshRevoker(r RefreshRevoker) *Service { s.refresh = r; return s }

// ForgotPassword always succeeds from the caller's point of view so usernames
// and emails cannot be enumerated.
func (s *Service) ForgotPassword(ctx context.Context, login, ip, ua string) {
	u, err := s.users.FindByUsername(ctx, login)
	if err != nil {
		u, err = s.users.FindByEmail(ctx, login)
	}
	if err != nil || u.Source != users.SourceLocal || u.Status != users.StatusActive || u.Email == "" {
		return
	}
	raw, hash, err := newToken()
	if err != nil {
		return
	}
	if err := s.tokens.Create(ctx, u.ID, PurposePasswordReset, hash, time.Now().Add(resetTTL)); err != nil {
		return
	}
	link := fmt.Sprintf("%s/reset-password?token=%s", s.issuer, raw)
	body := fmt.Sprintf("Hello %s,\n\nA password reset was requested for your account.\nOpen the link below within 1 hour to set a new password:\n\n%s\n\nIf you did not request this, ignore this message.", u.Username, link)
	_ = s.mail.Send(ctx, u.Email, "Password reset", body)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "password_reset_requested", TargetType: "user", TargetID: u.ID.String(), IP: ip, UserAgent: ua})
}

func (s *Service) ResetPassword(ctx context.Context, rawToken, newPassword, ip, ua string) error {
	if len(newPassword) < 8 {
		return errors.New("password must contain at least 8 characters")
	}
	userID, err := s.tokens.Consume(ctx, PurposePasswordReset, HashToken(rawToken))
	if err != nil {
		return ErrInvalidToken
	}
	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := s.users.SetPasswordHash(ctx, userID, hash); err != nil {
		return err
	}
	// A reset means the old credentials may be compromised: cut every session.
	_ = s.sessions.RevokeAllByUser(ctx, userID)
	if s.refresh != nil {
		_ = s.refresh.RevokeRefreshTokensByUser(ctx, userID)
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "password_reset_completed", TargetType: "user", TargetID: userID.String(), IP: ip, UserAgent: ua})
	return nil
}

func (s *Service) RequestEmailVerification(ctx context.Context, userID uuid.UUID) error {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.EmailVerified {
		return errors.New("email already verified")
	}
	raw, hash, err := newToken()
	if err != nil {
		return err
	}
	if err := s.tokens.Create(ctx, u.ID, PurposeEmailVerify, hash, time.Now().Add(verifyTTL)); err != nil {
		return err
	}
	link := fmt.Sprintf("%s/verify-email?token=%s", s.issuer, raw)
	body := fmt.Sprintf("Hello %s,\n\nConfirm your email address by opening the link below within 24 hours:\n\n%s", u.Username, link)
	return s.mail.Send(ctx, u.Email, "Verify your email", body)
}

func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	userID, err := s.tokens.Consume(ctx, PurposeEmailVerify, HashToken(rawToken))
	if err != nil {
		return ErrInvalidToken
	}
	if err := s.users.SetEmailVerified(ctx, userID, true); err != nil {
		return err
	}
	// Pending accounts become active once the email is proven.
	if u, ferr := s.users.FindByID(ctx, userID); ferr == nil && u.Status == users.StatusPending {
		u.Status = users.StatusActive
		_, _ = s.users.Update(ctx, u)
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "email_verified", TargetType: "user", TargetID: userID.String()})
	return nil
}

type EnrollResult struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

func (s *Service) MFAEnroll(ctx context.Context, userID uuid.UUID) (EnrollResult, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return EnrollResult{}, err
	}
	if u.MFAEnabled {
		return EnrollResult{}, ErrMFAState
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		return EnrollResult{}, err
	}
	enc, err := s.encryptor.Encrypt(secret)
	if err != nil {
		return EnrollResult{}, err
	}
	if err := s.users.SetMFA(ctx, userID, false, enc); err != nil {
		return EnrollResult{}, err
	}
	return EnrollResult{Secret: secret, OTPAuthURL: mfa.OTPAuthURL(issuerApp, u.Username, secret)}, nil
}

func (s *Service) MFAActivate(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.MFAEnabled || u.MFASecret == "" {
		return nil, ErrMFAState
	}
	secret, err := s.encryptor.Decrypt(u.MFASecret)
	if err != nil {
		return nil, err
	}
	if !mfa.Verify(secret, code, time.Now()) {
		return nil, ErrInvalidCode
	}
	if err := s.users.SetMFA(ctx, userID, true, u.MFASecret); err != nil {
		return nil, err
	}
	codes := make([]string, 0, 8)
	hashes := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		c, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, c)
		hashes = append(hashes, HashToken(c))
	}
	if err := s.recovery.Replace(ctx, userID, hashes); err != nil {
		return nil, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "mfa_enabled", TargetType: "user", TargetID: userID.String()})
	return codes, nil
}

func (s *Service) MFADisable(ctx context.Context, userID uuid.UUID, code string) error {
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if !u.MFAEnabled {
		return ErrMFAState
	}
	ok, err := s.VerifyCode(ctx, u, code)
	if err != nil || !ok {
		return ErrInvalidCode
	}
	if err := s.users.SetMFA(ctx, userID, false, ""); err != nil {
		return err
	}
	_ = s.recovery.DeleteAll(ctx, userID)
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "mfa_disabled", TargetType: "user", TargetID: userID.String()})
	return nil
}

// VerifyCode implements auth.MFAVerifier: accepts a current TOTP code or an
// unused recovery code.
func (s *Service) VerifyCode(ctx context.Context, u users.User, code string) (bool, error) {
	if u.MFASecret != "" {
		secret, err := s.encryptor.Decrypt(u.MFASecret)
		if err == nil && mfa.Verify(secret, code, time.Now()) {
			return true, nil
		}
	}
	used, err := s.recovery.Consume(ctx, u.ID, HashToken(code))
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return false, err
	}
	return used, nil
}
