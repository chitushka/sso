package broker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/netx"
	"github.com/google/uuid"
)

var (
	ErrProviderDisabled      = errors.New("identity provider is disabled")
	ErrBrokerFailed          = errors.New("external authentication failed")
	ErrVerifiedEmailRequired = errors.New("verified email is required for account provisioning")
	// ErrLinkRequiresMFA is returned when a brokered login matches, by email, a
	// local account that has MFA enabled. Auto-linking there would let the
	// external IdP bypass the user's second factor, so linking must be manual.
	ErrLinkRequiresMFA = errors.New("account has mfa enabled and must be linked manually")
)

type Service struct {
	repo        Repository
	auth        *auth.Service
	audit       audit.Repository
	issuer      string
	stateSecret []byte
	client      *http.Client
}

func NewService(repo Repository, authSvc *auth.Service, aud audit.Repository, issuer string, stateSecret []byte) *Service {
	client := netx.NewSafeHTTPClient(10 * time.Second)
	return &Service{repo: repo, auth: authSvc, audit: aud, issuer: issuer, stateSecret: stateSecret, client: client}
}

func (s *Service) List(ctx context.Context) ([]Provider, error) { return s.repo.List(ctx) }

// PublicProviders returns only what the login page needs.
func (s *Service) PublicProviders(ctx context.Context) ([]map[string]string, error) {
	all, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	out := []map[string]string{}
	for _, p := range all {
		if p.Enabled {
			out = append(out, map[string]string{"code": p.Code, "name": p.Name, "type": p.Type})
		}
	}
	return out, nil
}

func (s *Service) Create(ctx context.Context, p Provider) (Provider, error) {
	p.Code = strings.TrimSpace(strings.ToLower(p.Code))
	if p.Code == "" || p.ClientID == "" {
		return Provider{}, errors.New("code and client_id are required")
	}
	if p.Type == "" {
		p.Type = "oidc"
	}
	p = applyPreset(p)
	if p.AuthorizeURL == "" || p.TokenURL == "" || p.UserinfoURL == "" {
		return Provider{}, errors.New("authorize_url, token_url and userinfo_url are required for type oidc")
	}
	if err := validateProvider(p); err != nil {
		return Provider{}, err
	}
	out, err := s.repo.Create(ctx, p)
	if err != nil {
		return Provider{}, err
	}
	if err := audit.Write(ctx, s.audit, audit.Event{Action: "identity_provider_created", TargetType: "identity_provider", TargetID: out.ID.String()}); err != nil {
		return Provider{}, err
	}
	return out, nil
}

func (s *Service) Update(ctx context.Context, p Provider) (Provider, error) {
	p = applyPreset(p)
	if err := validateProvider(p); err != nil {
		return Provider{}, err
	}
	out, err := s.repo.Update(ctx, p)
	if err != nil {
		return Provider{}, err
	}
	if err := audit.Write(ctx, s.audit, audit.Event{Action: "identity_provider_updated", TargetType: "identity_provider", TargetID: out.ID.String()}); err != nil {
		return Provider{}, err
	}
	return out, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	return audit.Write(ctx, s.audit, audit.Event{Action: "identity_provider_deleted", TargetType: "identity_provider", TargetID: id.String()})
}

func validateProvider(p Provider) error {
	switch p.Type {
	case "google", "github", "oidc":
	default:
		return fmt.Errorf("unsupported identity provider type %q", p.Type)
	}
	if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.ClientID) == "" {
		return errors.New("name and client_id are required")
	}
	for field, raw := range map[string]string{
		"authorize_url": p.AuthorizeURL,
		"token_url":     p.TokenURL,
		"userinfo_url":  p.UserinfoURL,
	} {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("%s must be an absolute HTTPS URL without credentials or fragments", field)
		}
	}
	return nil
}

func (s *Service) callbackURL(code string) string {
	return s.issuer + "/oauth2/broker/" + url.PathEscape(code) + "/callback"
}

// Start builds the external authorize redirect with a signed state.
func (s *Service) Start(ctx context.Context, providerCode, continueURL string) (string, error) {
	p, err := s.repo.FindByCode(ctx, providerCode)
	if err != nil {
		return "", err
	}
	if !p.Enabled {
		return "", ErrProviderDisabled
	}
	p = applyPreset(p)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	signed, err := signState(s.stateSecret, state{Provider: p.Code, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Continue: continueURL, Exp: time.Now().Add(10 * time.Minute)})
	if err != nil {
		return "", err
	}
	u, err := url.Parse(p.AuthorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", s.callbackURL(p.Code))
	q.Set("scope", p.Scopes)
	q.Set("state", signed)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Callback verifies the state, exchanges the code, resolves or creates the
// local user and establishes an SSO session.
func (s *Service) Callback(ctx context.Context, providerCode, rawState, code string, in auth.LoginInput) (auth.LoginResult, string, error) {
	st, err := verifyState(s.stateSecret, rawState)
	if err != nil || st.Provider != providerCode {
		return auth.LoginResult{}, "", ErrBrokerFailed
	}
	p, err := s.repo.FindByCode(ctx, providerCode)
	if err != nil || !p.Enabled {
		return auth.LoginResult{}, "", ErrBrokerFailed
	}
	p = applyPreset(p)
	info, err := s.fetchIdentity(ctx, p, code)
	if err != nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "broker_login_failed", TargetType: "identity_provider", TargetID: p.Code, IP: in.IP, UserAgent: in.UserAgent})
		return auth.LoginResult{}, "", ErrBrokerFailed
	}
	resolution, err := s.repo.ResolveIdentity(ctx, p, info)
	if err != nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "broker_login_failed", TargetType: "identity_provider", TargetID: p.Code, IP: in.IP, UserAgent: in.UserAgent})
		return auth.LoginResult{}, "", err
	}
	u := resolution.User
	if resolution.UserCreated {
		_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "user_created", TargetType: "user", TargetID: u.ID.String()})
	}
	if resolution.IdentityCreated {
		_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "identity_linked", TargetType: "identity_provider", TargetID: p.Code})
	}
	res, err := s.auth.EstablishFederatedSession(ctx, u, in)
	if err != nil {
		return auth.LoginResult{}, "", err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "broker_login_success", TargetType: "identity_provider", TargetID: p.Code, IP: in.IP, UserAgent: in.UserAgent})
	return res, st.Continue, nil
}

func (s *Service) fetchIdentity(ctx context.Context, p Provider, code string) (IdentityClaims, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.callbackURL(p.Code)},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return IdentityClaims{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json") // GitHub answers form-encoded without it
	resp, err := s.client.Do(req)
	if err != nil {
		return IdentityClaims{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IdentityClaims{}, fmt.Errorf("token exchange failed: %s", resp.Status)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return IdentityClaims{}, fmt.Errorf("token exchange failed: %s", resp.Status)
	}
	ureq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoURL, nil)
	if err != nil {
		return IdentityClaims{}, err
	}
	ureq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	ureq.Header.Set("Accept", "application/json")
	uresp, err := s.client.Do(ureq)
	if err != nil {
		return IdentityClaims{}, err
	}
	defer func() { _ = uresp.Body.Close() }()
	if uresp.StatusCode < 200 || uresp.StatusCode >= 300 {
		return IdentityClaims{}, fmt.Errorf("userinfo request failed: %s", uresp.Status)
	}
	ubody, _ := io.ReadAll(io.LimitReader(uresp.Body, 1<<20))
	var m map[string]any
	if err := json.Unmarshal(ubody, &m); err != nil {
		return IdentityClaims{}, err
	}
	id := IdentityClaims{}
	if v, ok := m["sub"].(string); ok {
		id.Subject = v
	} else if v, ok := m["id"]; ok { // GitHub returns a numeric id
		id.Subject = fmt.Sprint(v)
	}
	if v, ok := m["email"].(string); ok {
		id.Email = v
	}
	// Only a boolean true is trusted. Providers that omit the claim (e.g. GitHub
	// /user) leave this false, so the email is never used to link accounts.
	if v, ok := m["email_verified"].(bool); ok {
		id.EmailVerified = v
	}
	for _, k := range []string{"preferred_username", "login", "name"} {
		if v, ok := m[k].(string); ok && v != "" {
			id.Username = v
			break
		}
	}
	if p.Type == "github" {
		email, err := s.fetchGitHubPrimaryEmail(ctx, tok.AccessToken)
		if err != nil {
			return IdentityClaims{}, err
		}
		id.Email = email
		id.EmailVerified = true
	}
	if id.Subject == "" {
		return IdentityClaims{}, errors.New("userinfo has no subject")
	}
	return id, nil
}

func (s *Service) fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github email request failed: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return primaryVerifiedGitHubEmail(body)
}

func primaryVerifiedGitHubEmail(body []byte) (string, error) {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}
	for _, email := range emails {
		if email.Primary && email.Verified && strings.TrimSpace(email.Email) != "" {
			return email.Email, nil
		}
	}
	return "", ErrVerifiedEmailRequired
}
