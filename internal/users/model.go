package users

import (
	"time"

	"github.com/google/uuid"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
	StatusPending Status = "pending"
	StatusDeleted Status = "deleted"
)

const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
)

type User struct {
	ID             uuid.UUID  `json:"id"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	PasswordHash   string     `json:"-"`
	Status         Status     `json:"status"`
	Source         string     `json:"source"`
	LDAPProviderID *uuid.UUID `json:"ldap_provider_id,omitempty"`
	LDAPDN         string     `json:"ldap_dn,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastLoginAt    *time.Time `json:"last_login_at,omitempty"`
}
