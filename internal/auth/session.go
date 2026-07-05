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
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	TokenHash string     `json:"-"`
	IP        string     `json:"ip"`
	UserAgent string     `json:"user_agent"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// SessionBrowser powers the self-service "my sessions" API; separate from
// SessionRepository so existing fakes keep compiling.
type SessionBrowser interface {
	ListByUser(ctx context.Context, userID uuid.UUID) ([]Session, error)
	RevokeByID(ctx context.Context, userID, sessionID uuid.UUID) error
	RevokeAllByUser(ctx context.Context, userID uuid.UUID) error
}
type SessionRepository interface {
	Create(ctx context.Context, s Session) (Session, error)
	FindByTokenHash(ctx context.Context, hash string) (Session, error)
	RevokeByTokenHash(ctx context.Context, hash string) error
	RevokeAllByUser(ctx context.Context, userID uuid.UUID) error
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
