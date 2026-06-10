package ldap

import (
	"context"
	"errors"
	"strings"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
)

type DirectoryClient interface {
	Test(ctx context.Context, p Provider) error
	Authenticate(ctx context.Context, p Provider, username, password string) (Identity, error)
}

type Service struct {
	repo   Repository
	client DirectoryClient
	audit  audit.Repository
}

func NewService(repo Repository, client DirectoryClient, audit audit.Repository) *Service {
	return &Service{repo: repo, client: client, audit: audit}
}

type ProviderInput struct {
	Name                 string `json:"name"`
	Host                 string `json:"host"`
	Port                 int    `json:"port"`
	UseTLS               bool   `json:"use_tls"`
	StartTLS             bool   `json:"start_tls"`
	BindDN               string `json:"bind_dn"`
	BindPassword         string `json:"bind_password"`
	BaseDN               string `json:"base_dn"`
	UserFilter           string `json:"user_filter"`
	UsernameAttribute    string `json:"username_attribute"`
	EmailAttribute       string `json:"email_attribute"`
	DisplayNameAttribute string `json:"display_name_attribute"`
	Enabled              *bool  `json:"enabled"`
}

func (s *Service) Create(ctx context.Context, in ProviderInput, ip, ua string) (Provider, error) {
	p, err := providerFromInput(in, Provider{})
	if err != nil {
		return Provider{}, err
	}
	created, err := s.repo.Create(ctx, p)
	if err != nil {
		return Provider{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "ldap_provider_created", TargetType: "ldap_provider", TargetID: created.ID.String(), IP: ip, UserAgent: ua})
	return created, nil
}

func (s *Service) List(ctx context.Context, limit, offset int) ([]Provider, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.List(ctx, limit, offset)
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (Provider, error) {
	return s.repo.FindByID(ctx, id)
}

func (s *Service) Update(ctx context.Context, id uuid.UUID, in ProviderInput, ip, ua string) (Provider, error) {
	current, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return Provider{}, err
	}
	p, err := providerFromInput(in, current)
	if err != nil {
		return Provider{}, err
	}
	p.ID = id
	updated, err := s.repo.Update(ctx, p)
	if err != nil {
		return Provider{}, err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "ldap_provider_updated", TargetType: "ldap_provider", TargetID: id.String(), IP: ip, UserAgent: ua})
	return updated, nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID, ip, ua string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "ldap_provider_deleted", TargetType: "ldap_provider", TargetID: id.String(), IP: ip, UserAgent: ua})
	return nil
}

func (s *Service) Test(ctx context.Context, id uuid.UUID) (TestResult, error) {
	p, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	if err := s.client.Test(ctx, p); err != nil {
		return TestResult{OK: false, Message: err.Error()}, nil
	}
	return TestResult{OK: true, Message: "ldap connection successful"}, nil
}

func (s *Service) Authenticate(ctx context.Context, username, password, ip, ua string) (Identity, error) {
	providers, err := s.repo.ListEnabled(ctx)
	if err != nil {
		return Identity{}, err
	}
	for _, p := range providers {
		identity, err := s.client.Authenticate(ctx, p, username, password)
		if err == nil {
			_ = s.audit.Write(ctx, audit.Event{Action: "ldap_login_success", TargetType: "ldap_provider", TargetID: p.ID.String(), IP: ip, UserAgent: ua})
			return identity, nil
		}
		if !errors.Is(err, ErrInvalidCredentials) && !errors.Is(err, storage.ErrNotFound) {
			_ = s.audit.Write(ctx, audit.Event{Action: "ldap_login_failed", TargetType: "ldap_provider", TargetID: p.ID.String(), IP: ip, UserAgent: ua})
			return Identity{}, err
		}
	}
	_ = s.audit.Write(ctx, audit.Event{Action: "ldap_login_failed", TargetType: "user", TargetID: username, IP: ip, UserAgent: ua})
	return Identity{}, ErrInvalidCredentials
}

func providerFromInput(in ProviderInput, current Provider) (Provider, error) {
	p := current
	if strings.TrimSpace(in.Name) != "" {
		p.Name = strings.TrimSpace(in.Name)
	}
	if strings.TrimSpace(in.Host) != "" {
		p.Host = strings.TrimSpace(in.Host)
	}
	if in.Port != 0 {
		p.Port = in.Port
	}
	if p.Port == 0 {
		p.Port = 389
	}
	p.UseTLS = in.UseTLS
	p.StartTLS = in.StartTLS
	if in.BindDN != "" {
		p.BindDN = strings.TrimSpace(in.BindDN)
	}
	if in.BindPassword != "" {
		p.BindPassword = in.BindPassword
	}
	if in.BaseDN != "" {
		p.BaseDN = strings.TrimSpace(in.BaseDN)
	}
	if strings.TrimSpace(in.UserFilter) != "" {
		p.UserFilter = strings.TrimSpace(in.UserFilter)
	}
	if p.UserFilter == "" {
		p.UserFilter = "(&(objectClass=user)(sAMAccountName={username}))"
	}
	if strings.TrimSpace(in.UsernameAttribute) != "" {
		p.UsernameAttribute = strings.TrimSpace(in.UsernameAttribute)
	}
	if p.UsernameAttribute == "" {
		p.UsernameAttribute = "sAMAccountName"
	}
	if strings.TrimSpace(in.EmailAttribute) != "" {
		p.EmailAttribute = strings.TrimSpace(in.EmailAttribute)
	}
	if p.EmailAttribute == "" {
		p.EmailAttribute = "mail"
	}
	if strings.TrimSpace(in.DisplayNameAttribute) != "" {
		p.DisplayNameAttribute = strings.TrimSpace(in.DisplayNameAttribute)
	}
	if p.DisplayNameAttribute == "" {
		p.DisplayNameAttribute = "displayName"
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	} else if current.ID == uuid.Nil {
		p.Enabled = true
	}
	if p.Name == "" || p.Host == "" || p.BindDN == "" || p.BindPassword == "" || p.BaseDN == "" {
		return Provider{}, errors.New("name, host, bind_dn, bind_password and base_dn are required")
	}
	if p.UseTLS && p.StartTLS {
		return Provider{}, errors.New("use_tls and start_tls are mutually exclusive")
	}
	return p, nil
}
