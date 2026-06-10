package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

type Client struct {
	dialTimeout time.Duration
}

func NewClient() *Client { return &Client{dialTimeout: 5 * time.Second} }

func (c *Client) Test(ctx context.Context, p Provider) error {
	conn, err := c.connect(ctx, p)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Bind(p.BindDN, p.BindPassword)
}

func (c *Client) Authenticate(ctx context.Context, p Provider, username, password string) (Identity, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return Identity{}, ErrInvalidCredentials
	}

	conn, err := c.connect(ctx, p)
	if err != nil {
		return Identity{}, err
	}
	defer conn.Close()

	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		return Identity{}, fmt.Errorf("ldap service bind failed: %w", err)
	}

	identity, err := c.searchUser(conn, p, username)
	if err != nil {
		return Identity{}, err
	}

	userConn, err := c.connect(ctx, p)
	if err != nil {
		return Identity{}, err
	}
	defer userConn.Close()

	if err := userConn.Bind(identity.DN, password); err != nil {
		return Identity{}, ErrInvalidCredentials
	}

	return identity, nil
}

func (c *Client) connect(ctx context.Context, p Provider) (*ldapv3.Conn, error) {
	addr := net.JoinHostPort(p.Host, fmt.Sprintf("%d", p.Port))
	dialer := &net.Dialer{Timeout: c.dialTimeout}

	if p.UseTLS {
		return ldapv3.DialURL("ldaps://"+addr, ldapv3.DialWithDialer(dialer), ldapv3.DialWithTLSConfig(&tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12}))
	}

	conn, err := ldapv3.DialURL("ldap://"+addr, ldapv3.DialWithDialer(dialer))
	if err != nil {
		return nil, err
	}

	if p.StartTLS {
		if err := conn.StartTLS(&tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12}); err != nil {
			conn.Close()
			return nil, err
		}
	}

	select {
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	default:
		return conn, nil
	}
}

func (c *Client) searchUser(conn *ldapv3.Conn, p Provider, username string) (Identity, error) {
	filter := strings.ReplaceAll(p.UserFilter, "{username}", ldapv3.EscapeFilter(username))
	attrs := uniqueNonEmpty([]string{p.UsernameAttribute, p.EmailAttribute, p.DisplayNameAttribute, "dn"})
	req := ldapv3.NewSearchRequest(
		p.BaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		attrs,
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return Identity{}, err
	}
	if len(res.Entries) != 1 {
		return Identity{}, ErrInvalidCredentials
	}
	entry := res.Entries[0]
	return Identity{
		ProviderID:  p.ID,
		DN:          entry.DN,
		Username:    firstNonEmpty(entry.GetAttributeValue(p.UsernameAttribute), username),
		Email:       entry.GetAttributeValue(p.EmailAttribute),
		DisplayName: entry.GetAttributeValue(p.DisplayNameAttribute),
		Source:      "ldap",
	}, nil
}

func uniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
