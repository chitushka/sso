package oauth

import (
	"github.com/google/uuid"
	"time"
)

type ClientType string

const (
	ClientConfidential ClientType = "confidential"
	ClientPublic       ClientType = "public"
)

type Client struct {
	ID               uuid.UUID  `json:"id"`
	ClientID         string     `json:"client_id"`
	ClientSecretHash *string    `json:"-"`
	Name             string     `json:"name"`
	Type             ClientType `json:"type"`
	RedirectURIs     []string   `json:"redirect_uris"`
	AllowedScopes    []string   `json:"allowed_scopes"`
	Enabled          bool       `json:"enabled"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}
type AuthorizationCode struct {
	ID                  uuid.UUID
	CodeHash            string
	ClientID            string
	UserID              uuid.UUID
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
	UsedAt              *time.Time
	CreatedAt           time.Time
}
