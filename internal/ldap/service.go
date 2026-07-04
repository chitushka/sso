package ldap

import (
	"context"
	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type Service struct {
	repo   Repository
	client DirectoryClient
	audit  audit.Repository
}

func NewService(repo Repository, client DirectoryClient, audit audit.Repository) *Service {
	return &Service{repo: repo, client: client, audit: audit}
}
func (s *Service) Create(ctx context.Context, p Provider) (Provider, error) {
	if p.Port == 0 {
		p.Port = 389
	}
	if p.UserFilter == "" {
		p.UserFilter = "(&(objectClass=user)(sAMAccountName={username}))"
	}
	if p.UsernameAttribute == "" {
		p.UsernameAttribute = "sAMAccountName"
	}
	if p.EmailAttribute == "" {
		p.EmailAttribute = "mail"
	}
	if p.DisplayNameAttribute == "" {
		p.DisplayNameAttribute = "displayName"
	}
	return s.repo.Create(ctx, p)
}
func (s *Service) List(ctx context.Context) ([]Provider, error) { return s.repo.List(ctx) }
func (s *Service) Test(ctx context.Context, p Provider) error   { return s.client.TestConnection(ctx, p) }
func (s *Service) Update(ctx context.Context, p Provider) (Provider, error) {
	// An empty bind password keeps the stored one so admins can update
	// connection settings without re-entering the secret.
	if p.BindPassword == "" {
		current, err := s.repo.FindByID(ctx, p.ID)
		if err != nil {
			return Provider{}, err
		}
		p.BindPassword = current.BindPassword
	}
	out, err := s.repo.Update(ctx, p)
	if err == nil {
		_ = s.audit.Write(ctx, audit.Event{Action: "ldap_provider_updated", TargetType: "ldap_provider", TargetID: out.ID.String()})
	}
	return out, err
}
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "ldap_provider_deleted", TargetType: "ldap_provider", TargetID: id.String()})
	return nil
}

type Authenticator struct {
	repo   Repository
	client DirectoryClient
	users  users.Repository
	audit  audit.Repository
}

func NewAuthenticator(repo Repository, client DirectoryClient, users users.Repository, audit audit.Repository) *Authenticator {
	return &Authenticator{repo: repo, client: client, users: users, audit: audit}
}
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (users.User, error) {
	p, err := a.repo.FirstEnabled(ctx)
	if err != nil {
		return users.User{}, err
	}
	id, err := a.client.Authenticate(ctx, p, username, password)
	if err != nil {
		_ = a.audit.Write(ctx, audit.Event{Action: "ldap_login_failed", TargetType: "user", TargetID: username})
		return users.User{}, err
	}
	dn := id.DN
	u, err := a.users.UpsertLDAP(ctx, users.User{Username: id.Username, Email: id.Email, Status: users.StatusActive, Source: users.SourceLDAP, LDAPProviderID: &id.ProviderID, LDAPDN: &dn})
	if err == nil {
		_ = a.audit.Write(ctx, audit.Event{ActorUserID: &u.ID, Action: "ldap_login_success", TargetType: "user", TargetID: u.ID.String()})
	}
	return u, err
}
