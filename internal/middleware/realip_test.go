package middleware

import (
	"github.com/chitushka/sso/internal/httpx"
	"net/http"
	"net/http/httptest"
	"testing"
)

func resolvedIP(t *testing.T, trusted []string, remoteAddr, xff string) string {
	t.Helper()
	var got string
	h := RealIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = httpx.ClientIP(r)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestRealIPIgnoresSpoofedXFFFromUntrustedPeer(t *testing.T) {
	// Прямой клиент не является доверенным proxy и пытается подменить IP.
	if ip := resolvedIP(t, []string{"10.0.0.0/8"}, "203.0.113.9:5555", "1.2.3.4"); ip != "203.0.113.9" {
		t.Fatalf("spoofed XFF must be ignored, got %s", ip)
	}
}

func TestRealIPHonorsXFFFromTrustedProxy(t *testing.T) {
	if ip := resolvedIP(t, []string{"10.0.0.0/8"}, "10.1.2.3:5555", "203.0.113.9"); ip != "203.0.113.9" {
		t.Fatalf("trusted proxy XFF must be honored, got %s", ip)
	}
}

func TestRealIPSkipsChainedTrustedProxies(t *testing.T) {
	// После клиента два доверенных узла дополнили цепочку.
	if ip := resolvedIP(t, []string{"10.0.0.0/8"}, "10.1.2.3:5555", "203.0.113.9, 10.9.9.9, 10.1.2.3"); ip != "203.0.113.9" {
		t.Fatalf("must pick rightmost untrusted, got %s", ip)
	}
}

func TestRealIPNoTrustedProxiesNeverTrustsXFF(t *testing.T) {
	if ip := resolvedIP(t, nil, "203.0.113.9:5555", "1.2.3.4"); ip != "203.0.113.9" {
		t.Fatalf("with no trusted proxies XFF must be ignored, got %s", ip)
	}
}
