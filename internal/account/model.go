package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

const (
	PurposePasswordReset = "password_reset"
	PurposeEmailVerify   = "email_verify"
)

// TokenRepository stores hashed one-time tokens (password reset, email verify).
type TokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, purpose, tokenHash string, expiresAt time.Time) error
	Consume(ctx context.Context, purpose, tokenHash string) (uuid.UUID, error)
}

// RecoveryCodeRepository stores hashed MFA recovery codes.
type RecoveryCodeRepository interface {
	Replace(ctx context.Context, userID uuid.UUID, codeHashes []string) error
	Consume(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error)
	DeleteAll(ctx context.Context, userID uuid.UUID) error
}

func newToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = HashToken(raw)
	return
}

func HashToken(raw string) string {
	s := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(s[:])
}

func newRecoveryCode() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil // 10 hex chars, e.g. 3f9c21ab04
}
