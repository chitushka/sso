package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/google/uuid"
)

type memUsers struct{ u users.User }

func (m *memUsers) Create(_ context.Context, u users.User) (users.User, error)     { return u, nil }
func (m *memUsers) UpsertLDAP(_ context.Context, u users.User) (users.User, error) { return u, nil }
func (m *memUsers) FindByID(_ context.Context, _ uuid.UUID) (users.User, error)    { return m.u, nil }
func (m *memUsers) FindByUsername(_ context.Context, username string) (users.User, error) {
	if username != m.u.Username {
		return users.User{}, storage.ErrNotFound
	}
	return m.u, nil
}
func (m *memUsers) List(_ context.Context, _, _ int) ([]users.User, error)         { return nil, nil }
func (m *memUsers) Update(_ context.Context, u users.User) (users.User, error)     { return u, nil }
func (m *memUsers) SetPasswordHash(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (m *memUsers) SetEmailVerified(_ context.Context, _ uuid.UUID, _ bool) error  { return nil }
func (m *memUsers) SetMFA(_ context.Context, _ uuid.UUID, _ bool, _ string) error  { return nil }
func (m *memUsers) SetMFACounter(_ context.Context, _ uuid.UUID, _ int64) error    { return nil }
func (m *memUsers) FindByEmail(_ context.Context, _ string) (users.User, error)    { return m.u, nil }
func (m *memUsers) TouchLastLogin(_ context.Context, _ uuid.UUID) error            { return nil }
func (m *memUsers) InvalidateTokens(_ context.Context, _ uuid.UUID) error          { return nil }
func (m *memUsers) TokensInvalidBefore(_ context.Context, _ uuid.UUID) (*time.Time, error) {
	return nil, nil
}
func (m *memUsers) Count(_ context.Context) (int64, error) { return 1, nil }

type memSessions struct{}

func (memSessions) Create(_ context.Context, s Session) (Session, error) { return s, nil }
func (memSessions) FindByTokenHash(_ context.Context, _ string) (Session, error) {
	return Session{}, storage.ErrNotFound
}
func (memSessions) RevokeByTokenHash(_ context.Context, _ string) error  { return nil }
func (memSessions) RevokeAllByUser(_ context.Context, _ uuid.UUID) error { return nil }

type memAudit struct{ actions []string }

func (m *memAudit) Write(_ context.Context, e audit.Event) error {
	m.actions = append(m.actions, e.Action)
	return nil
}

type memHasher struct{}

func (memHasher) Hash(p string) (string, error) { return "hash:" + p, nil }
func (memHasher) Verify(p, h string) (bool, error) {
	return h == "hash:"+p, nil
}

type memTokens struct{}

func (memTokens) Issue(_ users.User) (string, time.Time, error) {
	return "jwt", time.Now().Add(15 * time.Minute), nil
}
func (memTokens) IssueOAuthAccessToken(_ users.User, _, _ string) (string, time.Time, error) {
	return "jwt", time.Now().Add(15 * time.Minute), nil
}
func (memTokens) IssueClientCredentialsToken(_ users.User, _, _ string) (string, time.Time, error) {
	return "jwt", time.Now().Add(15 * time.Minute), nil
}

type memAttempts struct {
	attempts map[string]int
	locked   map[string]time.Time
}

func newMemAttempts() *memAttempts {
	return &memAttempts{attempts: map[string]int{}, locked: map[string]time.Time{}}
}
func (m *memAttempts) key(u, ip string) string { return u + "|" + ip }
func (m *memAttempts) Status(_ context.Context, u, ip string) (LoginAttemptStatus, error) {
	st := LoginAttemptStatus{Attempts: m.attempts[m.key(u, ip)]}
	if t, ok := m.locked[m.key(u, ip)]; ok {
		st.LockedUntil = &t
	}
	return st, nil
}
func (m *memAttempts) Fail(_ context.Context, u, ip string) (int, error) {
	m.attempts[m.key(u, ip)]++
	return m.attempts[m.key(u, ip)], nil
}
func (m *memAttempts) Lock(_ context.Context, u, ip string, until time.Time) error {
	m.locked[m.key(u, ip)] = until
	return nil
}
func (m *memAttempts) Reset(_ context.Context, u, ip string) error {
	delete(m.attempts, m.key(u, ip))
	delete(m.locked, m.key(u, ip))
	return nil
}

func newLockoutService(attempts *memAttempts, aud *memAudit) *Service {
	hash := "hash:correct-password"
	u := users.User{ID: uuid.New(), Username: "alice", Status: users.StatusActive, Source: users.SourceLocal, PasswordHash: &hash}
	return NewService(&memUsers{u: u}, memSessions{}, aud, memHasher{}, memTokens{}, time.Hour).WithLockout(attempts)
}

func TestLoginLocksAfterMaxFailures(t *testing.T) {
	attempts := newMemAttempts()
	aud := &memAudit{}
	svc := newLockoutService(attempts, aud)
	in := LoginInput{Username: "alice", Password: "wrong", IP: "1.2.3.4"}
	for i := 0; i < maxAttempts; i++ {
		if _, err := svc.Login(context.Background(), in); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: want ErrInvalidCredentials, got %v", i+1, err)
		}
	}
	// Now locked: even the correct password must be rejected.
	if _, err := svc.Login(context.Background(), LoginInput{Username: "alice", Password: "correct-password", IP: "1.2.3.4"}); !errors.Is(err, ErrLoginLocked) {
		t.Fatalf("want ErrLoginLocked, got %v", err)
	}
	locked := false
	for _, a := range aud.actions {
		if a == "login_locked" {
			locked = true
		}
	}
	if !locked {
		t.Fatal("expected login_locked audit event")
	}
}

func TestLoginRejectsEmptyPassword(t *testing.T) {
	attempts := newMemAttempts()
	svc := newLockoutService(attempts, &memAudit{})
	// An empty password must never authenticate, even for an existing user, and
	// must count as a failed attempt (defends against LDAP unauthenticated bind).
	if _, err := svc.Login(context.Background(), LoginInput{Username: "alice", Password: "", IP: "1.2.3.4"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials for empty password, got %v", err)
	}
	if attempts.attempts["alice|1.2.3.4"] != 1 {
		t.Fatalf("empty password must register a failed attempt, got %d", attempts.attempts["alice|1.2.3.4"])
	}
}

func TestLoginFromDifferentIPNotLocked(t *testing.T) {
	attempts := newMemAttempts()
	svc := newLockoutService(attempts, &memAudit{})
	in := LoginInput{Username: "alice", Password: "wrong", IP: "1.2.3.4"}
	for i := 0; i < maxAttempts; i++ {
		_, _ = svc.Login(context.Background(), in)
	}
	if _, err := svc.Login(context.Background(), LoginInput{Username: "alice", Password: "correct-password", IP: "5.6.7.8"}); err != nil {
		t.Fatalf("different IP must not be locked, got %v", err)
	}
}

func TestSuccessfulLoginResetsCounter(t *testing.T) {
	attempts := newMemAttempts()
	svc := newLockoutService(attempts, &memAudit{})
	for i := 0; i < maxAttempts-1; i++ {
		_, _ = svc.Login(context.Background(), LoginInput{Username: "alice", Password: "wrong", IP: "1.2.3.4"})
	}
	if _, err := svc.Login(context.Background(), LoginInput{Username: "alice", Password: "correct-password", IP: "1.2.3.4"}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if attempts.attempts["alice|1.2.3.4"] != 0 {
		t.Fatal("counter must be reset after successful login")
	}
}

type fakeMFAVerifier struct{ valid string }

func (f fakeMFAVerifier) VerifyCode(_ context.Context, _ users.User, code string) (bool, error) {
	return code == f.valid, nil
}

func TestMFALoginFlow(t *testing.T) {
	hash := "hash:correct-password"
	u := users.User{ID: uuid.New(), Username: "alice", Status: users.StatusActive, Source: users.SourceLocal, PasswordHash: &hash, MFAEnabled: true}
	issuer := NewJWTIssuer([]byte("0123456789abcdef0123456789abcdef"), 15*time.Minute)
	svc := NewService(&memUsers{u: u}, memSessions{}, &memAudit{}, memHasher{}, issuer, time.Hour).
		WithLockout(newMemAttempts()).
		WithMFA(fakeMFAVerifier{valid: "123456"}, issuer)

	res, err := svc.Login(context.Background(), LoginInput{Username: "alice", Password: "correct-password", IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !res.MFARequired || res.MFAToken == "" {
		t.Fatalf("expected mfa_required, got %+v", res)
	}
	if res.SessionToken != "" || res.AccessToken != "" {
		t.Fatal("no session may be issued before the second factor")
	}
	// The pending token must not pass BearerAuth.
	if claims, err := issuer.Verify(res.MFAToken); err != nil || claims.Purpose != "mfa" {
		t.Fatalf("mfa token must carry purpose=mfa, got %+v err %v", claims, err)
	}
	// Wrong code fails.
	if _, err := svc.CompleteMFALogin(context.Background(), res.MFAToken, "000000", LoginInput{IP: "1.2.3.4"}); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("want ErrInvalidMFACode, got %v", err)
	}
	// Correct code completes the login.
	final, err := svc.CompleteMFALogin(context.Background(), res.MFAToken, "123456", LoginInput{IP: "1.2.3.4"})
	if err != nil {
		t.Fatalf("complete mfa: %v", err)
	}
	if final.AccessToken == "" || final.SessionToken == "" {
		t.Fatalf("expected full session after second factor, got %+v", final)
	}
	// A regular access token must not work as an mfa token.
	if _, err := svc.CompleteMFALogin(context.Background(), final.AccessToken, "123456", LoginInput{IP: "1.2.3.4"}); err == nil {
		t.Fatal("access token must not be accepted as mfa token")
	}
}

func TestLockDurationGrowsAndCaps(t *testing.T) {
	if d := lockDuration(maxAttempts); d != baseLock {
		t.Fatalf("first lock: want %v, got %v", baseLock, d)
	}
	if d := lockDuration(maxAttempts + 1); d != 2*baseLock {
		t.Fatalf("second lock: want %v, got %v", 2*baseLock, d)
	}
	if d := lockDuration(maxAttempts + 100); d != maxLock {
		t.Fatalf("lock must cap at %v, got %v", maxLock, d)
	}
}
