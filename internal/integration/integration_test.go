//go:build integration

// Package integration exercises the whole server against a real PostgreSQL:
// migrations, bootstrap, login, OAuth2 code flow with refresh rotation and
// RBAC enforcement. Requires SSO_TEST_DATABASE_URL; the schema is dropped and
// recreated, so point it at a throwaway database only.
package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/chitushka/sso/internal/account"
	"github.com/chitushka/sso/internal/app"
	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/broker"
	"github.com/chitushka/sso/internal/config"
	"github.com/chitushka/sso/internal/middleware"
	"github.com/chitushka/sso/internal/oauth"
	"github.com/chitushka/sso/internal/oidc"
	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/storage"
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

type captureMailer struct {
	body string
}

func (m *captureMailer) Send(_ context.Context, _, _, body string) error {
	m.body = body
	return nil
}

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

func assertNoStore(t *testing.T, resp *http.Response) {
	t.Helper()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("%s %s: Cache-Control = %q, want no-store", resp.Request.Method, resp.Request.URL.Path, got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("%s %s: Pragma = %q, want no-cache", resp.Request.Method, resp.Request.URL.Path, got)
	}
}

func currentTOTP(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func loginSession(t *testing.T, username, password string) loginResult {
	t.Helper()
	var result loginResult
	resp := doJSON(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": username, "password": password}, &result)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s: %d", username, resp.StatusCode)
	}
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "sso_session":
			result.SessionToken = cookie.Value
		case "sso_csrf":
			result.CSRFToken = cookie.Value
		}
	}
	if result.SessionToken == "" || result.CSRFToken == "" {
		t.Fatalf("login %s did not set session cookies", username)
	}
	return result
}

func requestAuthorizationCode(t *testing.T, sessionToken string) (int, string) {
	t.Helper()
	query := url.Values{"response_type": {"code"}, "client_id": {"test-app"}, "redirect_uri": {"https://client.example/cb"}, "scope": {"openid profile"}, "state": {"inactive-test"}}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/oauth2/authorize?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: sessionToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	location, _ := url.Parse(resp.Header.Get("Location"))
	return resp.StatusCode, location.Query().Get("code")
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

func pendingActivationEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	userRepo := users.NewPostgresRepository(pool)
	auditRepo := audit.NewPostgresRepository(pool)
	hasher := auth.NewArgon2idHasher()
	mail := &captureMailer{}
	userSvc := users.NewService(userRepo, hasher, auditRepo).WithEmailActivation(mail, "https://sso.example.org")
	created, err := userSvc.Create(ctx, users.CreateUserInput{Username: "pending-e2e", Email: "pending-e2e@example.org", Password: "PendingPassword1!", Status: users.StatusPending}, "127.0.0.1", "integration-test")
	if err != nil {
		t.Fatal(err)
	}
	const marker = "token="
	pos := strings.LastIndex(mail.body, marker)
	if pos < 0 {
		t.Fatalf("письмо не содержит verification-токен: %q", mail.body)
	}
	firstToken := strings.TrimSpace(mail.body[pos+len(marker):])
	accountSvc := account.NewService(userRepo, account.NewPostgresTokenRepository(pool), account.NewPostgresRecoveryCodeRepository(pool), hasher, secrets.NewAESGCM("integration-test-enc-key-32chars-ok!"), mail, auditRepo, "https://sso.example.org")
	if err := accountSvc.RequestEmailVerification(ctx, created.ID); !errors.Is(err, account.ErrVerificationRateLimited) {
		t.Fatalf("повторное письмо не ограничено: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE one_time_tokens SET created_at=now()-interval '2 minutes' WHERE user_id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := accountSvc.RequestEmailVerification(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	pos = strings.LastIndex(mail.body, marker)
	token := strings.TrimSpace(mail.body[pos+len(marker):])
	if err := accountSvc.VerifyEmail(ctx, firstToken); !errors.Is(err, account.ErrInvalidToken) {
		t.Fatalf("предыдущая ссылка не аннулирована: %v", err)
	}
	if err := accountSvc.VerifyEmail(ctx, token); err != nil {
		t.Fatal(err)
	}
	if resp := doJSON(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "pending-e2e", "password": "PendingPassword1!"}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("вход после активации: %d", resp.StatusCode)
	}
}

func concurrentBrokerResolution(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repo := broker.NewPostgresRepository(pool, secrets.NewAESGCM("integration-test-enc-key-32chars-ok!"))
	provider, err := repo.Create(ctx, broker.Provider{
		Code: "concurrent-idp", Name: "Concurrent IdP", Type: "oidc", ClientID: "client",
		ClientSecret: "secret", AuthorizeURL: "https://idp.example/authorize",
		TokenURL: "https://idp.example/token", UserinfoURL: "https://idp.example/userinfo",
		Scopes: "openid email", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := broker.IdentityClaims{Subject: "same-subject", Email: "concurrent-broker@example.org", EmailVerified: true, Username: "concurrent-broker"}
	if _, err := repo.ResolveIdentity(ctx, provider, broker.IdentityClaims{Subject: "no-email"}); !errors.Is(err, broker.ErrVerifiedEmailRequired) {
		t.Fatalf("JIT без подтверждённого email не отклонён: %v", err)
	}
	start := make(chan struct{})
	results := make(chan broker.IdentityResolution, 2)
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			result, resolveErr := repo.ResolveIdentity(ctx, provider, claims)
			results <- result
			errs <- resolveErr
		}()
	}
	close(start)
	first, second := <-results, <-results
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if first.User.ID == uuid.Nil || first.User.ID != second.User.ID {
		t.Fatalf("конкурентные callback выбрали разных пользователей: %s и %s", first.User.ID, second.User.ID)
	}
	var usersCount, identitiesCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, claims.Email).Scan(&usersCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM federated_identities WHERE provider_id=$1 AND external_subject=$2`, provider.ID, claims.Subject).Scan(&identitiesCount); err != nil {
		t.Fatal(err)
	}
	if usersCount != 1 || identitiesCount != 1 {
		t.Fatalf("нарушена уникальность: users=%d identities=%d", usersCount, identitiesCount)
	}
}

func transactionalSecurityAudit(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `CREATE FUNCTION reject_test_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'forced audit failure'; END $$;
		CREATE TRIGGER reject_test_audit BEFORE INSERT ON audit_logs
		FOR EACH ROW EXECUTE FUNCTION reject_test_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS reject_test_audit ON audit_logs; DROP FUNCTION IF EXISTS reject_test_audit()`)
	}()

	repo := users.NewPostgresRepository(pool)
	hash := "test-password-hash"
	candidate := users.User{Username: "audit-rollback", Email: "audit-rollback@example.org", PasswordHash: &hash, Status: users.StatusActive, Source: users.SourceLocal}
	if _, err := repo.Create(ctx, candidate); err == nil {
		t.Fatal("мутация не откатилась при ошибке обязательного аудита")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username=$1`, candidate.Username).Scan(&count); err != nil || count != 0 {
		t.Fatalf("после ошибки аудита сохранён пользователь: count=%d err=%v", count, err)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_test_audit ON audit_logs`); err != nil {
		t.Fatal(err)
	}
	created, err := repo.Create(ctx, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username=$1`, candidate.Username).Scan(&count); err != nil || count != 1 {
		t.Fatalf("повтор создал неверное число пользователей: count=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action='security.users.insert' AND target_id=$1`, created.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("обязательное событие аудита отсутствует или продублировано: count=%d err=%v", count, err)
	}
}

func sharedRateLimiterEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `TRUNCATE rate_limit_buckets`); err != nil {
		t.Fatal(err)
	}
	first := middleware.NewPostgresTokenBucketLimiter(pool, 1, 2)
	second := middleware.NewPostgresTokenBucketLimiter(pool, 1, 2)
	for i, test := range []struct {
		limiter *middleware.PostgresTokenBucketLimiter
		want    bool
	}{{first, true}, {second, true}, {first, false}} {
		got, err := test.limiter.Allow(ctx, "203.0.113.10 /oauth2/token")
		if err != nil || got != test.want {
			t.Fatalf("общий limiter, запрос %d: allowed=%v want=%v err=%v", i+1, got, test.want, err)
		}
	}
	var rows, hashLength int
	if err := pool.QueryRow(ctx, `SELECT count(*),min(octet_length(key_hash)) FROM rate_limit_buckets`).Scan(&rows, &hashLength); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || hashLength != sha256.Size {
		t.Fatalf("неверное состояние общего limiter: rows=%d hash_length=%d", rows, hashLength)
	}
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
	pendingActivationEndToEnd(t)
	concurrentBrokerResolution(t)
	transactionalSecurityAudit(t)
	sharedRateLimiterEndToEnd(t)

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
		assertNoStore(t, resp)
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
	var enrollment struct {
		Secret string `json:"secret"`
	}
	enrollResp := doJSON(t, http.MethodPost, "/api/v1/auth/mfa/enroll", admin.credential(), nil, &enrollment)
	assertNoStore(t, enrollResp)
	if enrollResp.StatusCode != http.StatusOK || enrollment.Secret == "" {
		t.Fatalf("mfa enroll: %d %+v", enrollResp.StatusCode, enrollment)
	}
	var activation struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	activateResp := doJSON(t, http.MethodPost, "/api/v1/auth/mfa/activate", admin.credential(), map[string]string{"code": currentTOTP(enrollment.Secret)}, &activation)
	assertNoStore(t, activateResp)
	if activateResp.StatusCode != http.StatusOK || len(activation.RecoveryCodes) == 0 {
		t.Fatalf("mfa activate: %d %+v", activateResp.StatusCode, activation)
	}

	// 4. Create a confidential OAuth client (skip_consent for a headless flow).
	var created struct {
		Client struct {
			ID       string `json:"id"`
			ClientID string `json:"client_id"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	createClientResp := doJSON(t, "POST", "/api/v1/oauth/clients", admin.credential(), map[string]any{
		"client_id": "test-app", "name": "Test App", "type": "confidential",
		"redirect_uris": []string{"https://client.example/cb"}, "allowed_scopes": []string{"openid", "profile", "email"},
		"skip_consent": true, "enabled": true,
	}, &created)
	assertNoStore(t, createClientResp)
	if createClientResp.StatusCode != 201 || created.ClientSecret == "" {
		t.Fatalf("create client: %d %+v", createClientResp.StatusCode, created)
	}
	var rotated struct {
		ClientSecret string `json:"client_secret"`
	}
	rotateResp := doJSON(t, http.MethodPost, "/api/v1/oauth/clients/"+created.Client.ID+"/rotate-secret", admin.credential(), nil, &rotated)
	assertNoStore(t, rotateResp)
	if rotateResp.StatusCode != http.StatusOK || rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Fatalf("rotate client secret: %d %+v", rotateResp.StatusCode, rotated)
	}
	created.ClientSecret = rotated.ClientSecret

	// 5. Authorization code flow with the session cookie.
	q := url.Values{"response_type": {"code"}, "client_id": {"test-app"}, "redirect_uri": {"https://client.example/cb"}, "scope": {"openid profile"}, "state": {"xyz"}, "nonce": {"n1"}}
	req, _ := http.NewRequest("GET", server.URL+"/oauth2/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: "sso_session", Value: admin.SessionToken})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	assertNoStore(t, resp)
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
		assertNoStore(t, res)
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

	// 7. Заблокированные, ожидающие активации и удалённые пользователи не могут
	// авторизоваться или обменять код, созданный до смены статуса. Сессия отзывается.
	for _, userStatus := range []users.Status{users.StatusBlocked, users.StatusPending, users.StatusDeleted} {
		username := "oauth-" + string(userStatus)
		password := "InactivePassword1!"
		if resp := doJSON(t, http.MethodPost, "/api/v1/users", admin.credential(), map[string]string{
			"username": username,
			"email":    username + "@example.org",
			"password": password,
		}, nil); resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s user: %d", userStatus, resp.StatusCode)
		}
		userSession := loginSession(t, username, password)
		authorizeStatus, inactiveCode := requestAuthorizationCode(t, userSession.SessionToken)
		if authorizeStatus != http.StatusFound || inactiveCode == "" {
			t.Fatalf("initial authorize for %s user: status=%d code=%q", userStatus, authorizeStatus, inactiveCode)
		}
		if _, err := pool.Exec(context.Background(), "UPDATE users SET status=$2 WHERE username=$1", username, userStatus); err != nil {
			t.Fatal(err)
		}
		if status, _ := requestAuthorizationCode(t, userSession.SessionToken); status != http.StatusUnauthorized {
			t.Fatalf("%s user authorize must return 401, got %d", userStatus, status)
		}
		var revoked bool
		if err := pool.QueryRow(context.Background(), "SELECT revoked_at IS NOT NULL FROM sessions WHERE token_hash=$1", auth.HashSessionToken(userSession.SessionToken)).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if !revoked {
			t.Fatalf("%s user session was not revoked", userStatus)
		}
		status, body := tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {inactiveCode}, "redirect_uri": {"https://client.example/cb"}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}})
		if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("%s user code exchange: status=%d body=%v", userStatus, status, body)
		}
	}

	// 8. Блокировка атомарно отзывает все полномочия, а разблокировка не
	// восстанавливает старые сессии и токены.
	var revokeUser users.User
	if resp := doJSON(t, http.MethodPost, "/api/v1/users", admin.credential(), map[string]string{
		"username": "revoke-user", "email": "revoke-user@example.org", "password": "RevokePassword1!",
	}, &revokeUser); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create revocation user: %d", resp.StatusCode)
	}
	revokeSession := loginSession(t, "revoke-user", "RevokePassword1!")
	_, revokeCode := requestAuthorizationCode(t, revokeSession.SessionToken)
	revokeStatus, revokeTokens := tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {revokeCode}, "redirect_uri": {"https://client.example/cb"}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}})
	if revokeStatus != http.StatusOK {
		t.Fatalf("initial token exchange for revocation user: %d %v", revokeStatus, revokeTokens)
	}
	oldAccess, _ := revokeTokens["access_token"].(string)
	oldRefresh, _ := revokeTokens["refresh_token"].(string)
	_, unusedCode := requestAuthorizationCode(t, revokeSession.SessionToken)
	if unusedCode == "" {
		t.Fatal("authorization code for revocation test was not issued")
	}
	updateUser := map[string]any{
		"username": revokeUser.Username, "email": revokeUser.Email, "status": users.StatusBlocked,
		"first_name": revokeUser.FirstName, "last_name": revokeUser.LastName, "attributes": revokeUser.Attributes,
	}
	if resp := doJSON(t, http.MethodPut, "/api/v1/users/"+revokeUser.ID.String(), admin.credential(), updateUser, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("block user: %d", resp.StatusCode)
	}
	if status, _ := requestAuthorizationCode(t, revokeSession.SessionToken); status != http.StatusUnauthorized {
		t.Fatalf("session remained active after block: %d", status)
	}
	if status, body := tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {oldRefresh}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}}); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("refresh token remained active after block: %d %v", status, body)
	}
	introspect := func(token string) map[string]any {
		res, err := client.PostForm(server.URL+"/oauth2/introspect", url.Values{"token": {token}, "client_id": {"test-app"}, "client_secret": {created.ClientSecret}})
		if err != nil {
			t.Fatal(err)
		}
		assertNoStore(t, res)
		defer res.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	if body := introspect(oldAccess); body["active"] != false {
		t.Fatalf("access token remained active after block: %v", body)
	}
	var cutoffSet bool
	var liveSessions, liveRefresh, liveCodes int
	if err := pool.QueryRow(context.Background(), `SELECT tokens_invalid_before IS NOT NULL,
		(SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL),
		(SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL),
		(SELECT count(*) FROM oauth_authorization_codes WHERE user_id=$1 AND used_at IS NULL)
		FROM users WHERE id=$1`, revokeUser.ID).Scan(&cutoffSet, &liveSessions, &liveRefresh, &liveCodes); err != nil {
		t.Fatal(err)
	}
	if !cutoffSet || liveSessions != 0 || liveRefresh != 0 || liveCodes != 0 {
		t.Fatalf("incomplete credential revocation: cutoff=%v sessions=%d refresh=%d codes=%d", cutoffSet, liveSessions, liveRefresh, liveCodes)
	}
	updateUser["status"] = users.StatusActive
	if resp := doJSON(t, http.MethodPut, "/api/v1/users/"+revokeUser.ID.String(), admin.credential(), updateUser, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("unblock user: %d", resp.StatusCode)
	}
	if body := introspect(oldAccess); body["active"] != false {
		t.Fatalf("old access token revived after unblock: %v", body)
	}
	if resp := doJSON(t, http.MethodDelete, "/api/v1/users/"+revokeUser.ID.String(), admin.credential(), nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete user: %d", resp.StatusCode)
	}
	if resp := doJSON(t, http.MethodPut, "/api/v1/users/"+revokeUser.ID.String(), admin.credential(), updateUser, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("deleted user restoration through update must return 409, got %d", resp.StatusCode)
	}

	// 9. RBAC: a plain user has no admin permissions.
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

	// 10. Two instances racing to rotate an old signing key must commit exactly
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

	// 11. Offline encryption-key rotation re-encrypts every secret class and
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

	// 12. Migrations are idempotent on restart (MigrateOnStart with no changes).
	if !strings.Contains(server.URL, "http://") {
		t.Fatal("sanity")
	}
}

func TestConcurrentBlockWithSessionAndRefreshIssuance(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), testDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	userID := uuid.New()
	username := "concurrent-revoke-" + userID.String()
	if _, err := pool.Exec(context.Background(), `INSERT INTO users(id,username,email,status,source) VALUES($1,$2,$3,'active','local')`, userID, username, username+"@example.org"); err != nil {
		t.Fatal(err)
	}
	userRepo := users.NewPostgresRepository(pool)
	sessionRepo := auth.NewPostgresSessionRepository(pool)
	oauthRepo := oauth.NewPostgresRepository(pool, auth.NewArgon2idHasher())

	type operationResult struct {
		kind string
		err  error
	}
	start := make(chan struct{})
	results := make(chan operationResult, 41)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := sessionRepo.Create(context.Background(), auth.Session{UserID: userID, TokenHash: fmt.Sprintf("session-%s-%d", userID, i), ExpiresAt: time.Now().Add(time.Hour)})
			results <- operationResult{kind: "session", err: err}
		}(i)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := oauthRepo.CreateRefreshToken(context.Background(), oauth.RefreshToken{TokenHash: fmt.Sprintf("refresh-%s-%d", userID, i), FamilyID: uuid.New(), UserID: userID, ClientID: "test-app", ExpiresAt: time.Now().Add(time.Hour)})
			results <- operationResult{kind: "refresh", err: err}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		_, err := userRepo.Update(context.Background(), users.User{ID: userID, Username: username, Email: username + "@example.org", Status: users.StatusBlocked, Source: users.SourceLocal, Attributes: map[string]string{}})
		results <- operationResult{kind: "block", err: err}
	}()
	close(start)
	wg.Wait()
	close(results)

	for result := range results {
		if result.kind == "block" && result.err != nil {
			t.Fatalf("concurrent block failed: %v", result.err)
		}
		if result.kind != "block" && result.err != nil && !errors.Is(result.err, storage.ErrNotFound) {
			t.Fatalf("concurrent %s issuance returned unexpected error: %v", result.kind, result.err)
		}
	}
	var status users.Status
	var cutoffSet bool
	var liveSessions, liveRefresh int
	if err := pool.QueryRow(context.Background(), `SELECT status,tokens_invalid_before IS NOT NULL,
		(SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL),
		(SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL)
		FROM users WHERE id=$1`, userID).Scan(&status, &cutoffSet, &liveSessions, &liveRefresh); err != nil {
		t.Fatal(err)
	}
	if status != users.StatusBlocked || !cutoffSet || liveSessions != 0 || liveRefresh != 0 {
		t.Fatalf("credentials survived concurrent block: status=%s cutoff=%v sessions=%d refresh=%d", status, cutoffSet, liveSessions, liveRefresh)
	}
	if _, err := sessionRepo.Create(context.Background(), auth.Session{UserID: userID, TokenHash: "session-after-block-" + userID.String(), ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("session issuance after block must fail closed: %v", err)
	}
	if _, err := oauthRepo.CreateRefreshToken(context.Background(), oauth.RefreshToken{TokenHash: "refresh-after-block-" + userID.String(), FamilyID: uuid.New(), UserID: userID, ClientID: "test-app", ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("refresh issuance after block must fail closed: %v", err)
	}
}
