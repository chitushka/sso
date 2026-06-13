package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/google/uuid"
	"time"
)

type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	IP        string
	UserAgent string
	ExpiresAt time.Time
	RevokedAt *time.Time
}
type SessionRepository interface {
	Create(ctx context.Context, s Session) (Session, error)
	FindByTokenHash(ctx context.Context, hash string) (Session, error)
	RevokeByTokenHash(ctx context.Context, hash string) error
}

func NewSessionToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = HashSessionToken(raw)
	return
}
func HashSessionToken(raw string) string {
	s := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(s[:])
}
