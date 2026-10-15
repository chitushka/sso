package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type DirectoryClient interface {
	Authenticate(ctx context.Context, p Provider, username, password string) (Identity, error)
	TestConnection(ctx context.Context, p Provider) error
}

const defaultOperationTimeout = 10 * time.Second

type Client struct {
	requireTLS bool
	timeout    time.Duration
}

type clientConnection struct {
	conn *ldap.Conn
	stop func() bool
}

func NewClient() *Client { return &Client{timeout: defaultOperationTimeout} }
func (c *Client) WithTLSRequired(required bool) *Client {
	c.requireTLS = required
	return c
}

// WithTimeout задаёт общий предел для dial, TLS, bind и search.
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	if timeout > 0 {
		c.timeout = timeout
	}
	return c
}

func (c *Client) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = defaultOperationTimeout
	}
	return context.WithTimeout(parent, timeout)
}

func (c *Client) dial(ctx context.Context, p Provider) (*clientConnection, error) {
	if err := validateProviderTransport(p, c.requireTLS); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, operationError(ctx, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	closeRaw := func(err error) (*clientConnection, error) {
		stop()
		_ = raw.Close()
		return nil, operationError(ctx, err)
	}

	var wire net.Conn
	wire = raw
	if p.UseTLS {
		tlsConn := tls.Client(raw, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return closeRaw(err)
		}
		wire = tlsConn
	}
	conn := ldap.NewConn(wire, p.UseTLS)
	conn.Start()
	if p.StartTLS {
		if err := conn.StartTLS(&tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12}); err != nil {
			stop()
			_ = conn.Close()
			return nil, operationError(ctx, err)
		}
	}
	return &clientConnection{conn: conn, stop: stop}, nil
}

func (c *clientConnection) Close() {
	c.stop()
	_ = c.conn.Close()
}

func operationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return context.DeadlineExceeded
	}
	return err
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
	ctx, cancel := c.operationContext(ctx)
	defer cancel()
	connection, err := c.dial(ctx, p)
	if err != nil {
		return err
	}
	defer connection.Close()
	return operationError(ctx, connection.conn.Bind(p.BindDN, p.BindPassword))
}
func (c *Client) Authenticate(ctx context.Context, p Provider, username, password string) (Identity, error) {
	// An empty password turns the user bind below into an LDAP "unauthenticated
	// bind" (RFC 4513 §5.1.2), which many directories accept as success — that
	// would be an authentication bypass. Reject it before touching the server.
	if password == "" {
		return Identity{}, ErrInvalidCredentials
	}
	ctx, cancel := c.operationContext(ctx)
	defer cancel()
	connection, err := c.dial(ctx, p)
	if err != nil {
		return Identity{}, err
	}
	defer connection.Close()
	conn := connection.conn
	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		return Identity{}, operationError(ctx, err)
	}
	filter := strings.ReplaceAll(p.UserFilter, "{username}", ldap.EscapeFilter(username))
	attrs := []string{p.UsernameAttribute, p.EmailAttribute, "dn"}
	if p.GroupAttribute != "" {
		attrs = append(attrs, p.GroupAttribute)
	}
	req := ldap.NewSearchRequest(p.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false, filter, attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		return Identity{}, operationError(ctx, err)
	}
	if len(res.Entries) != 1 {
		return Identity{}, fmt.Errorf("ldap user not found")
	}
	e := res.Entries[0]
	if err := conn.Bind(e.DN, password); err != nil {
		return Identity{}, operationError(ctx, err)
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
