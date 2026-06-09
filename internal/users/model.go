package users

import (
	"github.com/google/uuid"
	"time"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
	StatusPending Status = "pending"
	StatusDeleted Status = "deleted"
)

type User struct {
	ID           uuid.UUID  `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Status       Status     `json:"status"`
	Source       string     `json:"source"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}
