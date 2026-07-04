package auth

import (
	"context"
	"errors"
	"time"
)

var ErrLoginLocked = errors.New("too many failed login attempts")

// Lockout policy: after maxAttempts failures the (username, IP) pair is locked
// for an exponentially growing duration, capped at maxLock. Counters decay
// after one hour of inactivity (handled in the repository).
const (
	maxAttempts = 5
	baseLock    = time.Minute
	maxLock     = 15 * time.Minute
)

type LoginAttemptStatus struct {
	Attempts    int
	LockedUntil *time.Time
}
type LoginAttemptRepository interface {
	Status(ctx context.Context, username, ip string) (LoginAttemptStatus, error)
	Fail(ctx context.Context, username, ip string) (int, error)
	Lock(ctx context.Context, username, ip string, until time.Time) error
	Reset(ctx context.Context, username, ip string) error
}

func lockDuration(attempts int) time.Duration {
	d := baseLock << (attempts - maxAttempts)
	if d > maxLock || d <= 0 {
		return maxLock
	}
	return d
}
