package broker

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/chitushka/sso/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type handlerRepository struct {
	provider     Provider
	loginState   LoginState
	consumeCalls int
}

func (r *handlerRepository) List(context.Context) ([]Provider, error) {
	return []Provider{r.provider}, nil
}
func (r *handlerRepository) FindByCode(context.Context, string) (Provider, error) {
	return r.provider, nil
}
func (r *handlerRepository) Create(_ context.Context, p Provider) (Provider, error) { return p, nil }
func (r *handlerRepository) Update(_ context.Context, p Provider) (Provider, error) { return p, nil }
func (r *handlerRepository) Delete(context.Context, uuid.UUID) error                { return nil }
func (r *handlerRepository) ResolveIdentity(context.Context, Provider, IdentityClaims) (IdentityResolution, error) {
	return IdentityResolution{}, nil
}
func (r *handlerRepository) CreateLoginState(_ context.Context, state LoginState) error {
	r.loginState = state
	return nil
}
func (r *handlerRepository) ConsumeLoginState(_ context.Context, stateHash []byte, providerCode string) (LoginState, error) {
	r.consumeCalls++
	if r.loginState.StateHash == nil || !bytes.Equal(r.loginState.StateHash, stateHash) || r.loginState.ProviderCode != providerCode {
		return LoginState{}, storage.ErrNotFound
	}
	state := r.loginState
	r.loginState = LoginState{}
	return state, nil
}

func testRouter(svc *Service) http.Handler {
	r := chi.NewRouter()
	passthrough := func(next http.Handler) http.Handler { return next }
	require := func(string, string) func(http.Handler) http.Handler { return passthrough }
	RegisterRoutes(r, svc, passthrough, require)
	return r
}

func TestBrokerLoginBindsStateToHTTPOnlyCookie(t *testing.T) {
	repo := &handlerRepository{provider: Provider{
		Code:         "example",
		Enabled:      true,
		AuthorizeURL: "https://idp.example.org/authorize",
		ClientID:     "client",
		Scopes:       "openid profile email",
	}}
	router := testRouter(NewService(repo, nil, nil, "https://sso.example.org"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://sso.example.org/oauth2/broker/example/login?continue=%2Fusers", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("начало входа: status=%d body=%s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("ожидалась одна state cookie, получено %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != brokerStateCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/oauth2/broker/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("небезопасные параметры state cookie: %+v", cookie)
	}
	redirect, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := redirect.Query().Get("state")
	if state == "" || state != cookie.Value {
		t.Fatal("state в redirect не совпадает с browser cookie")
	}
	if !bytes.Equal(repo.loginState.StateHash, hashLoginState(state)) || repo.loginState.ContinueURL != "/users" {
		t.Fatalf("сервер сохранил неверное состояние: %+v", repo.loginState)
	}

	// Другой браузер знает URL callback, но не имеет HttpOnly cookie.
	callback := httptest.NewRecorder()
	callbackRequest := httptest.NewRequest(http.MethodGet, "/oauth2/broker/example/callback?state="+url.QueryEscape(state)+"&code=code", nil)
	router.ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != "/login?broker_error=failed" {
		t.Fatalf("cross-browser callback принят: status=%d location=%q", callback.Code, callback.Header().Get("Location"))
	}
	if repo.consumeCalls != 0 {
		t.Fatal("cross-browser callback не должен потреблять серверный state")
	}
}

func TestCallbackRejectsInvalidStateAndClearsCookie(t *testing.T) {
	router := testRouter(NewService(nil, nil, nil, "https://sso.example.org"))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/broker/example/callback?state=invalid&code=code", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login?broker_error=failed" {
		t.Fatalf("callback: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("callback с одноразовым кодом допускает кэширование")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != brokerStateCookieName || cookies[0].MaxAge >= 0 {
		t.Fatalf("state cookie не очищена: %+v", cookies)
	}
}

func TestSafeContinueRejectsExternalAndAmbiguousTargets(t *testing.T) {
	for _, target := range []string{"https://evil.example", "//evil.example", `/\evil.example`, "/ok\r\nLocation: https://evil.example"} {
		if safeContinue(target) {
			t.Fatalf("опасный continue принят: %q", target)
		}
	}
	if !safeContinue("/account/settings") {
		t.Fatal("безопасный относительный continue отклонён")
	}
}
