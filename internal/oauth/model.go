package oauth

import (
	"time"

	"github.com/google/uuid"
)

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

type Client struct {
	ID               uuid.UUID  `json:"id"`
	ClientID         string     `json:"client_id"`
	ClientSecretHash string     `json:"-"`
	Name             string     `json:"name"`
	Type             ClientType `json:"type"`
	RedirectURIs     []string   `json:"redirect_uris"`
	AllowedScopes    []string   `json:"allowed_scopes"`
	Enabled          bool       `json:"enabled"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type AuthorizationCode struct {
	ID                  uuid.UUID  `json:"id"`
	CodeHash            string     `json:"-"`
	ClientID            uuid.UUID  `json:"client_id"`
	UserID              uuid.UUID  `json:"user_id"`
	RedirectURI         string     `json:"redirect_uri"`
	Scope               string     `json:"scope"`
	CodeChallenge       string     `json:"code_challenge,omitempty"`
	CodeChallengeMethod string     `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time  `json:"expires_at"`
	UsedAt              *time.Time `json:"used_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

type CreateClientInput struct {
	ClientID      string     `json:"client_id"`
	ClientSecret  string     `json:"client_secret"`
	Name          string     `json:"name"`
	Type          ClientType `json:"type"`
	RedirectURIs  []string   `json:"redirect_uris"`
	AllowedScopes []string   `json:"allowed_scopes"`
	Enabled       *bool      `json:"enabled"`
}

type UpdateClientInput struct {
	Name          string     `json:"name"`
	Type          ClientType `json:"type"`
	RedirectURIs  []string   `json:"redirect_uris"`
	AllowedScopes []string   `json:"allowed_scopes"`
	Enabled       *bool      `json:"enabled"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}
