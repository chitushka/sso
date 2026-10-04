package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type DirectoryClient interface {
	Authenticate(ctx context.Context, p Provider, username, password string) (Identity, error)
	TestConnection(ctx context.Context, p Provider) error
}
type Client struct{ requireTLS bool }

func NewClient() *Client { return &Client{} }
func (c *Client) WithTLSRequired(required bool) *Client {
	c.requireTLS = required
	return c
}
func (c *Client) dial(p Provider) (*ldap.Conn, error) {
	if err := validateProviderTransport(p, c.requireTLS); err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%s:%d", p.Host, p.Port)
	if p.UseTLS {
		return ldap.DialTLS("tcp", addr, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
	}
	conn, err := ldap.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if p.StartTLS {
		if err := conn.StartTLS(&tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12}); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func validateProviderTransport(p Provider, requireTLS bool) error {
	if p.UseTLS && p.StartTLS {
		return ErrConflictingTLSModes
	}
	if requireTLS && !p.UseTLS && !p.StartTLS {
		return ErrTLSRequired
	}
	return nil
}
func (c *Client) TestConnection(ctx context.Context, p Provider) error {
	conn, err := c.dial(p)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return conn.Bind(p.BindDN, p.BindPassword)
}
func (c *Client) Authenticate(ctx context.Context, p Provider, username, password string) (Identity, error) {
	// An empty password turns the user bind below into an LDAP "unauthenticated
	// bind" (RFC 4513 §5.1.2), which many directories accept as success — that
	// would be an authentication bypass. Reject it before touching the server.
	if password == "" {
		return Identity{}, ErrInvalidCredentials
	}
	conn, err := c.dial(p)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		return Identity{}, err
	}
	filter := strings.ReplaceAll(p.UserFilter, "{username}", ldap.EscapeFilter(username))
	attrs := []string{p.UsernameAttribute, p.EmailAttribute, "dn"}
	if p.GroupAttribute != "" {
		attrs = append(attrs, p.GroupAttribute)
	}
	req := ldap.NewSearchRequest(p.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false, filter, attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		return Identity{}, err
	}
	if len(res.Entries) != 1 {
		return Identity{}, fmt.Errorf("ldap user not found")
	}
	e := res.Entries[0]
	if err := conn.Bind(e.DN, password); err != nil {
		return Identity{}, err
	}
	email := e.GetAttributeValue(p.EmailAttribute)
	uname := e.GetAttributeValue(p.UsernameAttribute)
	if uname == "" {
		uname = username
	}
	var groups []string
	if p.GroupAttribute != "" {
		groups = e.GetAttributeValues(p.GroupAttribute)
	}
	return Identity{Username: uname, Email: email, DN: e.DN, ProviderID: p.ID, Groups: groups}, nil
}
