package oidc

import (
	"context"
	"net/http"
	"testing"
)

func TestSafeDialContextRejectsNonPublicLiteralBeforeDial(t *testing.T) {
	for _, address := range []string{
		"127.0.0.1:443",
		"10.0.0.1:443",
		"169.254.169.254:443",
		"[::1]:443",
		"[fc00::1]:443",
	} {
		t.Run(address, func(t *testing.T) {
			conn, err := safeDialContext(context.Background(), "tcp", address)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("unexpected connection")
			}
			if err == nil {
				t.Fatal("expected non-public address to be rejected")
			}
		})
	}
}

func TestBackchannelClientDisablesProxyAndRedirects(t *testing.T) {
	client := newBackchannelHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("unexpected transport type")
	}
	if transport.Proxy != nil {
		t.Fatal("backchannel client must not use environment proxies")
	}
	if client.CheckRedirect == nil {
		t.Fatal("redirect policy is not configured")
	}
}
