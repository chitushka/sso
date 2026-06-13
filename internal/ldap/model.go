package ldap

import (
	"github.com/google/uuid"
	"time"
)

type Provider struct {
	ID                   uuid.UUID `json:"id"`
	Name                 string    `json:"name"`
	Host                 string    `json:"host"`
	Port                 int       `json:"port"`
	UseTLS               bool      `json:"use_tls"`
	StartTLS             bool      `json:"start_tls"`
	BindDN               string    `json:"bind_dn"`
	BindPassword         string    `json:"bind_password,omitempty"`
	BaseDN               string    `json:"base_dn"`
	UserFilter           string    `json:"user_filter"`
	UsernameAttribute    string    `json:"username_attribute"`
	EmailAttribute       string    `json:"email_attribute"`
	DisplayNameAttribute string    `json:"display_name_attribute"`
	Enabled              bool      `json:"enabled"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}
type Identity struct {
	Username   string
	Email      string
	DN         string
	ProviderID uuid.UUID
}
