package broker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

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

type FederatedIdentity struct {
	ProviderID      uuid.UUID `json:"provider_id"`
	ExternalSubject string    `json:"external_subject"`
	UserID          uuid.UUID `json:"user_id"`
	Email           string    `json:"email"`
	CreatedAt       time.Time `json:"created_at"`
}

type Repository interface {
	List(ctx context.Context) ([]Provider, error)
	FindByCode(ctx context.Context, code string) (Provider, error)
	Create(ctx context.Context, p Provider) (Provider, error)
	Update(ctx context.Context, p Provider) (Provider, error)
	Delete(ctx context.Context, id uuid.UUID) error
	FindIdentity(ctx context.Context, providerID uuid.UUID, subject string) (FederatedIdentity, error)
	LinkIdentity(ctx context.Context, fi FederatedIdentity) error
}

// applyPreset fills the endpoint URLs for well-known provider types so admins
// only have to supply client_id/client_secret.
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

// state is the HMAC-signed round-trip payload protecting the broker flow
// against CSRF and callback forgery.
type state struct {
	Provider string    `json:"p"`
	Nonce    string    `json:"n"`
	Continue string    `json:"c"`
	Exp      time.Time `json:"e"`
}

var errBadState = errors.New("invalid state")

func signState(secret []byte, s state) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyState(secret []byte, raw string) (state, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return state{}, errBadState
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return state{}, errBadState
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return state{}, errBadState
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return state{}, errBadState
	}
	var s state
	if err := json.Unmarshal(payload, &s); err != nil {
		return state{}, errBadState
	}
	if time.Now().After(s.Exp) {
		return state{}, errBadState
	}
	return s, nil
}
