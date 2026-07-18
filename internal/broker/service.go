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
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

var (
	ErrProviderDisabled = errors.New("identity provider is disabled")
	ErrBrokerFailed     = errors.New("external authentication failed")
	// ErrLinkRequiresMFA is returned when a brokered login matches, by email, a
	// local account that has MFA enabled. Auto-linking there would let the
	// external IdP bypass the user's second factor, so linking must be manual.
	ErrLinkRequiresMFA = errors.New("account has mfa enabled and must be linked manually")
)

type Service struct {
	repo        Repository
	users       users.Repository
	auth        *auth.Service
	audit       audit.Repository
	issuer      string
	stateSecret []byte
	client      *http.Client
}

func NewService(repo Repository, usersRepo users.Repository, authSvc *auth.Service, aud audit.Repository, issuer string, stateSecret []byte) *Service {
	return &Service{repo: repo, users: usersRepo, auth: authSvc, audit: aud, issuer: issuer, stateSecret: stateSecret, client: &http.Client{Timeout: 10 * time.Second}}
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
	out, err := s.repo.Create(ctx, p)
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "identity_provider_created", TargetType: "identity_provider", TargetID: out.ID.String()})
	}
	return out, err
}

func (s *Service) Update(ctx context.Context, p Provider) (Provider, error) {
	p = applyPreset(p)
	out, err := s.repo.Update(ctx, p)
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "identity_provider_updated", TargetType: "identity_provider", TargetID: out.ID.String()})
	}
	return out, err
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	err := s.repo.Delete(ctx, id)
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "identity_provider_deleted", TargetType: "identity_provider", TargetID: id.String()})
	}
	return err
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
	u, err := s.resolveUser(ctx, p, info)
	if err != nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "broker_login_failed", TargetType: "identity_provider", TargetID: p.Code, IP: in.IP, UserAgent: in.UserAgent})
		return auth.LoginResult{}, "", err
	}
	res, err := s.auth.EstablishFederatedSession(ctx, u, in)
	if err != nil {
		return auth.LoginResult{}, "", err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "broker_login_success", TargetType: "identity_provider", TargetID: p.Code, IP: in.IP, UserAgent: in.UserAgent})
	return res, st.Continue, nil
}

type externalIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
}

func (s *Service) fetchIdentity(ctx context.Context, p Provider, code string) (externalIdentity, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.callbackURL(p.Code)},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return externalIdentity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json") // GitHub answers form-encoded without it
	resp, err := s.client.Do(req)
	if err != nil {
		return externalIdentity{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return externalIdentity{}, fmt.Errorf("token exchange failed: %s", resp.Status)
	}
	ureq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoURL, nil)
	if err != nil {
		return externalIdentity{}, err
	}
	ureq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	ureq.Header.Set("Accept", "application/json")
	uresp, err := s.client.Do(ureq)
	if err != nil {
		return externalIdentity{}, err
	}
	defer func() { _ = uresp.Body.Close() }()
	ubody, _ := io.ReadAll(io.LimitReader(uresp.Body, 1<<20))
	var m map[string]any
	if err := json.Unmarshal(ubody, &m); err != nil {
		return externalIdentity{}, err
	}
	id := externalIdentity{}
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
	if id.Subject == "" {
		return externalIdentity{}, errors.New("userinfo has no subject")
	}
	return id, nil
}

func (s *Service) resolveUser(ctx context.Context, p Provider, info externalIdentity) (users.User, error) {
	if fi, err := s.repo.FindIdentity(ctx, p.ID, info.Subject); err == nil {
		return s.users.FindByID(ctx, fi.UserID)
	}
	// Link to an existing account only when the IdP asserts a *verified* email.
	// Without that, anyone able to set an arbitrary email at the provider could
	// claim a local account. An unverified/absent email → provision a new one (JIT).
	var u users.User
	var err error
	if info.Email != "" && info.EmailVerified {
		u, err = s.users.FindByEmail(ctx, info.Email)
	} else {
		err = storage.ErrNotFound
	}
	switch {
	case err == nil:
		// Never auto-attach a federated login to an MFA-protected account: that
		// would silently bypass the user's second factor.
		if u.MFAEnabled {
			return users.User{}, ErrLinkRequiresMFA
		}
	case errors.Is(err, storage.ErrNotFound):
		if u, err = s.provisionUser(ctx, p, info); err != nil {
			return users.User{}, err
		}
	default:
		return users.User{}, err
	}
	if err := s.repo.LinkIdentity(ctx, FederatedIdentity{ProviderID: p.ID, ExternalSubject: info.Subject, UserID: u.ID, Email: info.Email}); err != nil {
		return users.User{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "identity_linked", TargetType: "identity_provider", TargetID: p.Code})
	return u, nil
}

func (s *Service) provisionUser(ctx context.Context, p Provider, info externalIdentity) (users.User, error) {
	username := info.Username
	if username == "" {
		if i := strings.Index(info.Email, "@"); i > 0 {
			username = info.Email[:i]
		} else {
			username = p.Code + "-" + info.Subject
		}
	}
	u, err := s.users.Create(ctx, users.User{Username: username, Email: info.Email, Status: users.StatusActive, Source: users.SourceFederated})
	if errors.Is(err, storage.ErrConflict) {
		// Username taken by someone else — retry once with a random suffix.
		suffix := make([]byte, 3)
		_, _ = rand.Read(suffix)
		u, err = s.users.Create(ctx, users.User{Username: username + "-" + base64.RawURLEncoding.EncodeToString(suffix), Email: info.Email, Status: users.StatusActive, Source: users.SourceFederated})
	}
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "user_created", TargetType: "user", TargetID: u.ID.String()})
	}
	return u, err
}
