package oidc

import (
	"net/http"
	"testing"
)

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
