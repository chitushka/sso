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

// TokenCacheInvalidator evicts a user's cached access state so a password reset
// takes effect immediately instead of after the cache TTL.
type TokenCacheInvalidator interface {
	Invalidate(userID uuid.UUID)
}

type Service struct {
	users      users.Repository
	tokens     CredentialRepository
	recovery   RecoveryCodeRepository
	passwords  auth.PasswordHasher
	encryptor  secrets.Encryptor
	mail       mailer.Mailer
	audit      audit.Repository
	tokenCache TokenCacheInvalidator
	issuer     string
}

func NewService(users users.Repository, tokens CredentialRepository, recovery RecoveryCodeRepository, passwords auth.PasswordHasher, encryptor secrets.Encryptor, mail mailer.Mailer, aud audit.Repository, issuer string) *Service {
	return &Service{users: users, tokens: tokens, recovery: recovery, passwords: passwords, encryptor: encryptor, mail: mail, audit: aud, issuer: issuer}
}

// WithTokenCache wires the access-state cache so a password reset busts it at once.
func (s *Service) WithTokenCache(c TokenCacheInvalidator) *Service { s.tokenCache = c; return s }

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
	if err := users.ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	userID, err := s.tokens.ResetPassword(ctx, HashToken(rawToken), hash)
	if errors.Is(err, storage.ErrNotFound) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if s.tokenCache != nil {
		s.tokenCache.Invalidate(userID)
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "password_reset_completed", TargetType: "user", TargetID: userID.String(), IP: ip, UserAgent: ua})
	return nil
}

// ChangePassword requires the current password and revokes every existing
// credential after the new password is stored.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	if err := users.ValidatePassword(newPassword); err != nil {
		return err
	}
	u, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.Source != users.SourceLocal || u.PasswordHash == nil {
		return errors.New("password is managed externally for this account")
	}
	ok, err := s.passwords.Verify(oldPassword, *u.PasswordHash)
	if err != nil || !ok {
		return errors.New("current password is incorrect")
	}
	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}
	if err := s.tokens.ChangePassword(ctx, userID, *u.PasswordHash, hash); err != nil {
		return err
	}
	if s.tokenCache != nil {
		s.tokenCache.Invalidate(userID)
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &userID, Action: "password_changed", TargetType: "user", TargetID: userID.String()})
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
	userID, err := s.tokens.VerifyEmail(ctx, HashToken(rawToken))
	if errors.Is(err, storage.ErrNotFound) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
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
	if err := s.tokens.ActivateMFA(ctx, userID, u.MFASecret, hashes); err != nil {
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
		if err == nil {
			if ok, counter := mfa.VerifyWithCounter(secret, code, time.Now()); ok {
				consumed, err := s.users.ConsumeMFACounter(ctx, u.ID, int64(counter))
				if err != nil {
					return false, err
				}
				return consumed, nil
			}
		}
	}
	used, err := s.recovery.Consume(ctx, u.ID, HashToken(code))
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return false, err
	}
	return used, nil
}
