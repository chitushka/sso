package users

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Password policy, shared by every flow that sets a password (bootstrap, admin
// create, self-service reset/change) so the rules cannot drift apart.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 128 // bound argon2id input; longer adds no security, only cost
)

// ValidatePassword enforces the length policy. Length is the dominant factor for
// password strength (NIST SP 800-63B), so no arbitrary composition rules.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLen {
		return errors.New("password must contain at least 12 characters")
	}
	if len(pw) > MaxPasswordLen {
		return errors.New("password must not exceed 128 characters")
	}
	return nil
}

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
	StatusPending Status = "pending"
	StatusDeleted Status = "deleted"
)
const (
	SourceLocal     = "local"
	SourceLDAP      = "ldap"
	SourceFederated = "federated"
)

type User struct {
	ID            uuid.UUID         `json:"id"`
	Username      string            `json:"username"`
	Email         string            `json:"email"`
	PasswordHash  *string           `json:"-"`
	Status        Status            `json:"status"`
	Source        string            `json:"source"`
	FirstName     string            `json:"first_name"`
	LastName      string            `json:"last_name"`
	Attributes    map[string]string `json:"attributes"`
	EmailVerified bool              `json:"email_verified"`
	MFAEnabled    bool              `json:"mfa_enabled"`
	MFASecret     string            `json:"-"`
	// MFALastUsedCounter is the last accepted TOTP time-step (replay guard).
	MFALastUsedCounter int64      `json:"-"`
	LDAPProviderID     *uuid.UUID `json:"ldap_provider_id,omitempty"`
	LDAPDN             *string    `json:"ldap_dn,omitempty"`
	// TokensInvalidBefore invalidates every access token issued at or before it.
	TokensInvalidBefore *time.Time `json:"-"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
}
