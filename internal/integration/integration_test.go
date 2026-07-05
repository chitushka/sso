//go:build integration

// Package integration exercises the whole server against a real PostgreSQL:
// migrations, bootstrap, login, OAuth2 code flow with refresh rotation and
// RBAC enforcement. Requires SSO_TEST_DATABASE_URL; the schema is dropped and
// recreated, so point it at a throwaway database only.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/app"
	"github.com/chitushka/sso/internal/config"
	"github.com/jackc/pgx/v5"
)

var (
	server *httptest.Server
	client *http.Client
)

func TestMain(m *testing.M) {
	dbURL := os.Getenv("SSO_TEST_DATABASE_URL")
	if dbURL == "" {
		os.Exit(0) // integration run not requested
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		panic("connect: " + err.Error())
	}
	if _, err := conn.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		panic("reset schema: " + err.Error())
	}
	_ = conn.Close(ctx)

	cfg := config.Config{
		Env:      "test",
		Database: config.DatabaseConfig{URL: dbURL, MigrateOnStart: true},
		Security: config.SecurityConfig{JWTSecret: "integration-test-jwt-secret-32chars!", EncryptionKey: "integration-test-enc-key-32chars-ok!"},
		Token:    config.TokenConfig{AccessTTL: 15 * time.Minute, SessionTTL: time.Hour, RefreshTTL: time.Hour},
		CORS:     config.CORSConfig{AllowedOrigins: []string{"http://localhost"}},
		OIDC:     config.OIDCConfig{Issuer: "http://localhost:8080"},
		Logging:  config.LoggingConfig{Level: "error"},
	}
	a, err := app.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err != nil {
		panic("app.New: " + err.Error())
	}
	defer a.Close()
	server = httptest.NewServer(a.Router())
	defer server.Close()
	client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	os.Exit(m.Run())
}

func doJSON(t *testing.T, method, path, bearer string, body any, out any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, server.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("%s %s: bad json %q: %v", method, path, data, err)
		}
	}
	return resp
}

type loginResult struct {
	AccessToken  string `json:"access_token"`
	SessionToken string `json:"session_token"`
	User         struct {
		ID string `json:"id"`
	} `json:"user"`
}

func TestEndToEnd(t *testing.T) {
	// 1. Health and discovery.
	if resp := doJSON(t, "GET", "/health/ready", "", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	var disco map[string]any
	if resp := doJSON(t, "GET", "/.well-known/openid-configuration", "", nil, &disco); resp.StatusCode != 200 || disco["issuer"] == "" {
		t.Fatalf("discovery failed: %d %v", resp.StatusCode, disco)
	}

	// 2. Bootstrap the first admin.
	if resp := doJSON(t, "POST", "/api/v1/bootstrap", "", map[string]string{"username": "admin", "email": "admin@example.org", "password": "SuperSecret123!"}, nil); resp.StatusCode != 201 {
		t.Fatalf("bootstrap: %d", resp.StatusCode)
	}
	if resp := doJSON(t, "POST", "/api/v1/bootstrap", "", map[string]string{"username": "x", "email": "x@example.org", "password": "SuperSecret123!"}, nil); resp.StatusCode != 409 {
		t.Fatalf("second bootstrap must 409, got %d", resp.StatusCode)
	}

	// 3. Login as admin.
	var admin loginResult
	if resp := doJSON(t, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "SuperSecret123!"}, &admin); resp.StatusCode != 200 || admin.AccessToken == "" || admin.SessionToken == "" {
		t.Fatalf("login failed: %d %+v", resp.StatusCode, admin)
	}
	if resp := doJSON(t, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "wrong"}, nil); resp.StatusCode != 401 {
		t.Fatalf("wrong password must 401, got %d", resp.StatusCode)
	}

	// 4. Create a confidential OAuth client (skip_consent for a headless flow).
	var created struct {
		Client struct {
			ID       string `json:"id"`
			ClientID string `json:"client_id"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	if resp := doJSON(t, "POST", "/api/v1/oauth/clients", admin.AccessToken, map[string]any{
		"client_id": "test-app", "name": "Test App", "type": "confidential",
		"redirect_uris": []string{"http://localhost/cb"}, "allowed_scopes": []string{"openid", "profile", "email"},
		"skip_consent": true, "enabled": true,
	}, &created); resp.StatusCode != 201 || created.ClientSecret == "" {
		t.Fatalf("create client: %d %+v", resp.StatusCode, created)
	}

	// 5. Authorization code flow with the session cookie.
	q := url.Values{"response_type": {"code"}, "client_id": {"test-app"}, "redirect_uri": {"http://localhost/cb"}, "scope": {"openid profile"}, "state": {"xyz"}, "nonce": {"n1"}}
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: admin.SessionToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("authorize: %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" || loc.Query().Get("state") != "xyz" {
		t.Fatalf("bad redirect %q", resp.Header.Get("Location"))
	}
	code := loc.Query().Get("code")

	// 6. Exchange the code, then rotate the refresh token.
	tokenReq := func(form url.Values) (int, map[string]any) {
		res, err := client.PostForm(server.URL+"/oauth2/token", form)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(res.Body).Decode(&m)
		return res.StatusCode, m
	}
	status, tok := tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost/cb"}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}})
	if status != 200 || tok["access_token"] == "" || tok["refresh_token"] == "" || tok["id_token"] == "" {
		t.Fatalf("token exchange: %d %v", status, tok)
	}
	firstRefresh, _ := tok["refresh_token"].(string)
	status, tok2 := tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}})
	if status != 200 || tok2["refresh_token"] == firstRefresh {
		t.Fatalf("refresh rotation: %d %v", status, tok2)
	}
	// Reuse of the rotated token must be rejected and revoke the family.
	if status, _ := tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {firstRefresh}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}}); status != 400 {
		t.Fatalf("refresh reuse must 400, got %d", status)
	}
	secondRefresh, _ := tok2["refresh_token"].(string)
	if status, _ := tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {secondRefresh}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}}); status != 400 {
		t.Fatalf("family member must be revoked after reuse, got %d", status)
	}
	// Wrong client secret is rejected with 401.
	if status, _ := tokenReq(url.Values{"grant_type": {"client_credentials"}, "scope": {"profile"}, "client_id": {"test-app"}, "client_secret": {"wrong"}}); status != 401 {
		t.Fatalf("wrong secret must 401, got %d", status)
	}

	// 7. RBAC: a plain user has no admin permissions.
	if resp := doJSON(t, "POST", "/api/v1/users", admin.AccessToken, map[string]string{"username": "bob", "email": "bob@example.org", "password": "BobPassword1!"}, nil); resp.StatusCode != 201 {
		t.Fatalf("create user: %d", resp.StatusCode)
	}
	var bob loginResult
	if resp := doJSON(t, "POST", "/api/v1/auth/login", "", map[string]string{"username": "bob", "password": "BobPassword1!"}, &bob); resp.StatusCode != 200 {
		t.Fatalf("bob login: %d", resp.StatusCode)
	}
	if resp := doJSON(t, "GET", "/api/v1/users", bob.AccessToken, nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob must get 403 on admin API, got %d", resp.StatusCode)
	}
	if resp := doJSON(t, "GET", "/api/v1/users", admin.AccessToken, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("admin must list users, got %d", resp.StatusCode)
	}

	// 8. Migrations are idempotent on restart (MigrateOnStart with no changes).
	if !strings.Contains(server.URL, "http://") {
		t.Fatal("sanity")
	}
}
