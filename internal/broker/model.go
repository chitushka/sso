package broker

import (
	"context"
	"time"

	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type Provider struct {
	ID           uuid.UUID `json:"id"`
	Code         string    `json:"code"`
	Name         string    `json:"name"`
	Type         string    `json:"type"` // google | github | oidc
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty"`
	AuthorizeURL string    `json:"authorize_url"`
	TokenURL     string    `json:"token_url"`
	UserinfoURL  string    `json:"userinfo_url"`
	Scopes       string    `json:"scopes"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type LoginState struct {
	StateHash    []byte
	ProviderCode string
	ContinueURL  string
	ExpiresAt    time.Time
}

type IdentityClaims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
}

type IdentityResolution struct {
	User            users.User
	UserCreated     bool
	IdentityCreated bool
}

type Repository interface {
	List(ctx context.Context) ([]Provider, error)
	FindByCode(ctx context.Context, code string) (Provider, error)
	Create(ctx context.Context, p Provider) (Provider, error)
	Update(ctx context.Context, p Provider) (Provider, error)
	Delete(ctx context.Context, id uuid.UUID) error
	CreateLoginState(ctx context.Context, state LoginState) error
	ConsumeLoginState(ctx context.Context, stateHash []byte, providerCode string) (LoginState, error)
	ResolveIdentity(ctx context.Context, provider Provider, claims IdentityClaims) (IdentityResolution, error)
}

// applyPreset заполняет адреса известных провайдеров, чтобы администратору
// оставалось указать только client_id и client_secret.
func applyPreset(p Provider) Provider {
	switch p.Type {
	case "google":
		if p.AuthorizeURL == "" {
			p.AuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"
		}
		if p.TokenURL == "" {
			p.TokenURL = "https://oauth2.googleapis.com/token"
		}
		if p.UserinfoURL == "" {
			p.UserinfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		}
	case "github":
		if p.AuthorizeURL == "" {
			p.AuthorizeURL = "https://github.com/login/oauth/authorize"
		}
		if p.TokenURL == "" {
			p.TokenURL = "https://github.com/login/oauth/access_token"
		}
		if p.UserinfoURL == "" {
			p.UserinfoURL = "https://api.github.com/user"
		}
		if p.Scopes == "" || p.Scopes == "openid profile email" {
			p.Scopes = "read:user user:email"
		}
	}
	return p
}
