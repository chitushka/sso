package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func forwardedScheme(t *testing.T, trusted []string, remoteAddr, proto string) (string, string) {
	t.Helper()
	var gotScheme string
	var gotHeader string
	h := RealIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotScheme = r.URL.Scheme
		gotHeader = r.Header.Get("X-Forwarded-Proto")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-Proto", proto)
	h.ServeHTTP(httptest.NewRecorder(), req)
	return gotScheme, gotHeader
}

func TestRealIPHonorsForwardedProtoFromTrustedProxy(t *testing.T) {
	scheme, header := forwardedScheme(t, []string{"10.0.0.0/8"}, "10.1.2.3:443", "https")
	if scheme != "https" {
		t.Fatalf("expected https scheme, got %q", scheme)
	}
	if header != "" {
		t.Fatal("forwarded proto must be removed before downstream handlers")
	}
}

func TestRealIPIgnoresForwardedProtoFromUntrustedPeer(t *testing.T) {
	scheme, header := forwardedScheme(t, []string{"10.0.0.0/8"}, "203.0.113.9:443", "https")
	if scheme != "" {
		t.Fatalf("untrusted forwarded proto must be ignored, got %q", scheme)
	}
	if header != "" {
		t.Fatal("untrusted forwarded proto must be stripped")
	}
}
