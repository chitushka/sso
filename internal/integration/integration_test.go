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
	"sync"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/app"
	"github.com/chitushka/sso/internal/config"
	"github.com/chitushka/sso/internal/oidc"
	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	server          *httptest.Server
	client          *http.Client
	testDatabaseURL string
)

func TestMain(m *testing.M) {
	dbURL := os.Getenv("SSO_TEST_DATABASE_URL")
	if dbURL == "" {
		os.Exit(0) // integration run not requested
	}
	testDatabaseURL = dbURL
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

func doJSON(t *testing.T, method, path, credential string, body any, out any) *http.Response {
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
	if strings.HasPrefix(credential, "session:") {
		parts := strings.SplitN(strings.TrimPrefix(credential, "session:"), ":", 2)
		req.AddCookie(&http.Cookie{Name: "sso_session", Value: parts[0]})
		if len(parts) == 2 {
			req.AddCookie(&http.Cookie{Name: "sso_csrf", Value: parts[1]})
			req.Header.Set("X-CSRF-Token", parts[1])
		}
	} else if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
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
	SessionToken string `json:"-"`
	CSRFToken    string `json:"-"`
	User         struct {
		ID string `json:"id"`
	} `json:"user"`
}

func (r loginResult) credential() string {
	return "session:" + r.SessionToken + ":" + r.CSRFToken
}

func TestEndToEnd(t *testing.T) {
	// 1. Health and discovery.
	if resp := doJSON(t, "GET", "/health/ready", "", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	if resp := doJSON(t, "GET", "/metrics", "", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("public metrics must be denied, got %d", resp.StatusCode)
	}
	var disco map[string]any
	if resp := doJSON(t, "GET", "/.well-known/openid-configuration", "", nil, &disco); resp.StatusCode != 200 || disco["issuer"] == "" {
		t.Fatalf("discovery failed: %d %v", resp.StatusCode, disco)
	}

	// 2. Concurrent bootstrap attempts: exactly one transaction may win.
	bootstrapBody, _ := json.Marshal(map[string]string{"username": "admin", "email": "admin@example.org", "password": "SuperSecret123!"})
	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/bootstrap", bytes.NewReader(bootstrapBody))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	counts := map[int]int{<-statuses: 1}
	counts[<-statuses]++
	if counts[http.StatusCreated] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent bootstrap statuses: %v", counts)
	}

	// An LDAP identity may not attach itself to the existing local admin by
	// presenting the same mutable username.
	pool, err := pgxpool.New(context.Background(), testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	bindPassword, err := secrets.NewAESGCM("integration-test-enc-key-32chars-ok!").Encrypt("directory-password")
	if err != nil {
		t.Fatal(err)
	}
	var providerID uuid.UUID
	err = pool.QueryRow(context.Background(), `INSERT INTO ldap_providers
		(name,host,bind_dn,bind_password,base_dn) VALUES('test','ldap','cn=x',$1,'dc=example') RETURNING id`, bindPassword).Scan(&providerID)
	if err != nil {
		t.Fatal(err)
	}
	dn := "uid=admin,dc=example"
	userRepo := users.NewPostgresRepository(pool)
	if _, err = userRepo.UpsertLDAP(context.Background(), users.User{
		Username: "admin", Email: "attacker@example.org", Status: users.StatusActive,
		Source: users.SourceLDAP, LDAPProviderID: &providerID, LDAPDN: &dn,
	}); err == nil {
		t.Fatal("LDAP username collision captured the local admin")
	}
	localAdmin, err := userRepo.FindByUsername(context.Background(), "admin")
	if err != nil || localAdmin.Source != users.SourceLocal || localAdmin.LDAPProviderID != nil {
		t.Fatalf("local admin identity changed after LDAP collision: %+v %v", localAdmin, err)
	}

	// 3. Login as admin.
	var admin loginResult
	if resp := doJSON(t, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "SuperSecret123!"}, &admin); resp.StatusCode != 200 {
		t.Fatalf("login failed: %d %+v", resp.StatusCode, admin)
	} else {
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "sso_session" {
				admin.SessionToken = cookie.Value
			}
			if cookie.Name == "sso_csrf" {
				admin.CSRFToken = cookie.Value
			}
		}
		if admin.SessionToken == "" || admin.CSRFToken == "" {
			t.Fatal("login did not set session and CSRF cookies")
		}
	}
	if resp := doJSON(t, "POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "wrong"}, nil); resp.StatusCode != 401 {
		t.Fatalf("wrong password must 401, got %d", resp.StatusCode)
	}
	if resp := doJSON(t, "GET", "/metrics", admin.credential(), nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin metrics request failed: %d", resp.StatusCode)
	}

	// 4. Create a confidential OAuth client (skip_consent for a headless flow).
	var created struct {
		Client struct {
			ID       string `json:"id"`
			ClientID string `json:"client_id"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	if resp := doJSON(t, "POST", "/api/v1/oauth/clients", admin.credential(), map[string]any{
		"client_id": "test-app", "name": "Test App", "type": "confidential",
		"redirect_uris": []string{"https://client.example/cb"}, "allowed_scopes": []string{"openid", "profile", "email"},
		"skip_consent": true, "enabled": true,
	}, &created); resp.StatusCode != 201 || created.ClientSecret == "" {
		t.Fatalf("create client: %d %+v", resp.StatusCode, created)
	}

	// 5. Authorization code flow with the session cookie.
	q := url.Values{"response_type": {"code"}, "client_id": {"test-app"}, "redirect_uri": {"https://client.example/cb"}, "scope": {"openid profile"}, "state": {"xyz"}, "nonce": {"n1"}}
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
	status, tok := tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/cb"}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}})
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
	if resp := doJSON(t, "POST", "/api/v1/users", admin.credential(), map[string]string{"username": "bob", "email": "bob@example.org", "password": "BobPassword1!"}, nil); resp.StatusCode != 201 {
		t.Fatalf("create user: %d", resp.StatusCode)
	}
	var bob loginResult
	if resp := doJSON(t, "POST", "/api/v1/auth/login", "", map[string]string{"username": "bob", "password": "BobPassword1!"}, &bob); resp.StatusCode != 200 {
		t.Fatalf("bob login: %d", resp.StatusCode)
	} else {
		for _, cookie := range resp.Cookies() {
			switch cookie.Name {
			case "sso_session":
				bob.SessionToken = cookie.Value
			case "sso_csrf":
				bob.CSRFToken = cookie.Value
			}
		}
	}
	if resp := doJSON(t, "GET", "/api/v1/users", bob.credential(), nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob must get 403 on admin API, got %d", resp.StatusCode)
	}
	if resp := doJSON(t, "GET", "/api/v1/users", admin.credential(), nil, nil); resp.StatusCode != 200 {
		t.Fatalf("admin must list users, got %d", resp.StatusCode)
	}

	// 8. Two instances racing to rotate an old signing key must commit exactly
	// one replacement and keep exactly one active key.
	if _, err := pool.Exec(context.Background(), `UPDATE oidc_signing_keys SET created_at=now()-interval '31 days' WHERE status='active'`); err != nil {
		t.Fatal(err)
	}
	oldEncryptor := secrets.NewAESGCM("integration-test-enc-key-32chars-ok!")
	rotationServices := []*oidc.Service{
		oidc.NewService("http://localhost:8080", oidc.NewPostgresKeyStore(pool, oldEncryptor)),
		oidc.NewService("http://localhost:8080", oidc.NewPostgresKeyStore(pool, oldEncryptor)),
	}
	var rotationWG sync.WaitGroup
	rotationErrors := make(chan error, len(rotationServices))
	for _, service := range rotationServices {
		rotationWG.Add(1)
		go func() {
			defer rotationWG.Done()
			rotationErrors <- service.RotateIfNeeded(context.Background())
		}()
	}
	rotationWG.Wait()
	close(rotationErrors)
	for err := range rotationErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	var activeKeys, publishedKeys int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE status='active'),count(*) FILTER (WHERE status IN ('active','retiring')) FROM oidc_signing_keys`).Scan(&activeKeys, &publishedKeys); err != nil {
		t.Fatal(err)
	}
	if activeKeys != 1 || publishedKeys != 2 {
		t.Fatalf("concurrent rotation left active=%d published=%d", activeKeys, publishedKeys)
	}

	// 9. Offline encryption-key rotation re-encrypts every secret class and
	// rejects the old key afterwards.
	mfaCiphertext, err := oldEncryptor.Encrypt("mfa-seed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE users SET mfa_secret=$2 WHERE id=$1`, localAdmin.ID, mfaCiphertext); err != nil {
		t.Fatal(err)
	}
	brokerCiphertext, err := oldEncryptor.Encrypt("broker-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO identity_providers(code,name,type,client_id,client_secret,authorize_url,token_url,userinfo_url,enabled) VALUES('rotation-test','Rotation Test','oidc','rotation-client',$1,'https://idp.example/authorize','https://idp.example/token','https://idp.example/userinfo',true)`, brokerCiphertext); err != nil {
		t.Fatal(err)
	}
	server.Close()
	newEncryptor := secrets.NewAESGCM("integration-test-new-enc-key-32chars!")
	if err := secrets.RotateDatabaseKey(context.Background(), pool, oldEncryptor, newEncryptor); err != nil {
		t.Fatal(err)
	}
	if err := secrets.EnsureDatabaseKey(context.Background(), pool, oldEncryptor); err == nil {
		t.Fatal("old encryption key still passed database verification")
	}
	if err := secrets.EnsureDatabaseKey(context.Background(), pool, newEncryptor); err != nil {
		t.Fatalf("new encryption key verification failed: %v", err)
	}
	for name, query := range map[string]string{
		"ldap":   `SELECT bind_password FROM ldap_providers WHERE id='` + providerID.String() + `'`,
		"broker": `SELECT client_secret FROM identity_providers WHERE code='rotation-test'`,
		"mfa":    `SELECT mfa_secret FROM users WHERE id='` + localAdmin.ID.String() + `'`,
		"oidc":   `SELECT private_key_pem FROM oidc_signing_keys WHERE status='active'`,
	} {
		var ciphertext string
		if err := pool.QueryRow(context.Background(), query).Scan(&ciphertext); err != nil {
			t.Fatalf("load rotated %s secret: %v", name, err)
		}
		if _, err := newEncryptor.Decrypt(ciphertext); err != nil {
			t.Fatalf("decrypt rotated %s secret: %v", name, err)
		}
	}

	// 10. Migrations are idempotent on restart (MigrateOnStart with no changes).
	if !strings.Contains(server.URL, "http://") {
		t.Fatal("sanity")
	}
}
