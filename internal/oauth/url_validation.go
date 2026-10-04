package oauth

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/chitushka/sso/internal/netx"
)

var ErrInvalidClientMetadata = errors.New("invalid oauth client metadata")

func validateClientURLs(clientType ClientType, redirectURIs, postLogoutRedirectURIs []string, backchannelLogoutURI string) error {
	if clientType != ClientConfidential && clientType != ClientPublic {
		return fmt.Errorf("%w: unsupported client type", ErrInvalidClientMetadata)
	}
	for _, raw := range redirectURIs {
		if err := validateBrowserRedirectURI(raw, clientType); err != nil {
			return fmt.Errorf("%w: redirect_uri %q: %v", ErrInvalidClientMetadata, raw, err)
		}
	}
	for _, raw := range postLogoutRedirectURIs {
		if err := validateBrowserRedirectURI(raw, clientType); err != nil {
			return fmt.Errorf("%w: post_logout_redirect_uri %q: %v", ErrInvalidClientMetadata, raw, err)
		}
	}
	if backchannelLogoutURI != "" {
		if err := validateBackchannelLogoutURI(backchannelLogoutURI); err != nil {
			return fmt.Errorf("%w: backchannel_logout_uri: %v", ErrInvalidClientMetadata, err)
		}
	}
	return nil
}

func parseAbsoluteURI(raw string) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, errors.New("must be a non-empty absolute URI without surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return nil, errors.New("must be an absolute hierarchical URI with a host")
	}
	if u.User != nil {
		return nil, errors.New("userinfo is not allowed")
	}
	if u.Fragment != "" {
		return nil, errors.New("fragments are not allowed")
	}
	return u, nil
}

func validateBrowserRedirectURI(raw string, clientType ClientType) error {
	u, err := parseAbsoluteURI(raw)
	if err != nil {
		return err
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if clientType != ClientPublic || !isLoopbackIPLiteral(u.Hostname()) {
			return errors.New("HTTP is allowed only for public clients using an IP-literal loopback host")
		}
		return nil
	default:
		return errors.New("scheme must be HTTPS, or HTTP for a public loopback client")
	}
}

func validateBackchannelLogoutURI(raw string) error {
	u, err := parseAbsoluteURI(raw)
	if err != nil {
		return err
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("scheme must be HTTPS")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if strings.Contains(host, "%") {
		return errors.New("scoped IP addresses are not allowed")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("local hosts are not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && !netx.IsPublicIP(ip) {
		return errors.New("non-public IP addresses are not allowed")
	}
	return nil
}

func isLoopbackIPLiteral(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
