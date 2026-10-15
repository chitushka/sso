package broker

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestCallbackRejectsInvalidState(t *testing.T) {
	r := chi.NewRouter()
	passthrough := func(next http.Handler) http.Handler { return next }
	require := func(string, string) func(http.Handler) http.Handler { return passthrough }
	RegisterRoutes(r, NewService(nil, nil, nil, "https://sso.example.org", []byte("state-secret")), passthrough, require)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/broker/example/callback?state=invalid&code=code", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login?broker_error=failed" {
		t.Fatalf("callback: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("callback с одноразовым кодом допускает кэширование")
	}
}

func TestSafeContinueRejectsExternalAndAmbiguousTargets(t *testing.T) {
	for _, target := range []string{"https://evil.example", "//evil.example", `/\\evil.example`, "/ok\r\nLocation: https://evil.example"} {
		if safeContinue(target) {
			t.Fatalf("опасный continue принят: %q", target)
		}
	}
	if !safeContinue("/account/settings") {
		t.Fatal("безопасный относительный continue отклонён")
	}
}
