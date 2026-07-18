package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/chitushka/sso/internal/account"
	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/bootstrap"
	"github.com/chitushka/sso/internal/broker"
	"github.com/chitushka/sso/internal/config"
	"github.com/chitushka/sso/internal/dbmigrate"
	"github.com/chitushka/sso/internal/health"
	"github.com/chitushka/sso/internal/ldap"
	"github.com/chitushka/sso/internal/mailer"
	"github.com/chitushka/sso/internal/middleware"
	"github.com/chitushka/sso/internal/oauth"
	"github.com/chitushka/sso/internal/oidc"
	"github.com/chitushka/sso/internal/rbac"
	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/users"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	pool   *pgxpool.Pool
	router http.Handler
}

func New(ctx context.Context, cfg config.Config, logger *slog.Logger, version string) (*App, error) {
	if cfg.Database.MigrateOnStart {
		if err := dbmigrate.Up(cfg.Database.URL); err != nil {
			return nil, err
		}
		logger.Info("database migrations applied")
	}
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	userRepo := users.NewPostgresRepository(pool)
	// Short-TTL cache in front of the per-request revocation check so BearerAuth
	// does not hit the DB on every authenticated request; block and "sign out
	// everywhere" bust it explicitly for immediate effect.
	accessCache := auth.NewCachedTokenChecker(userRepo, auth.AccessCacheTTL)
	sessionRepo := auth.NewPostgresSessionRepository(pool)
	auditRepo := audit.NewPostgresRepository(pool)
	rbacRepo := rbac.NewPostgresRepository(pool)
	rbacSvc := rbac.NewService(rbacRepo, auditRepo).WithGroups(rbacRepo)
	passwords := auth.NewArgon2idHasher()
	tokens := auth.NewJWTIssuer([]byte(cfg.Security.JWTSecret), cfg.Token.AccessTTL)
	encryptor := secrets.NewAESGCM(cfg.Security.EncryptionKey)
	ldapRepo := ldap.NewPostgresRepository(pool, encryptor)
	ldapClient := ldap.NewClient()
	ldapSvc := ldap.NewService(ldapRepo, ldapClient, auditRepo)
	ldapAuth := ldap.NewAuthenticator(ldapRepo, ldapClient, userRepo, auditRepo).WithGroupSync(rbacRepo)
	loginAttempts := auth.NewPostgresLoginAttemptRepository(pool)
	mail := mailer.New(mailer.Config{Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Username: cfg.SMTP.Username, Password: cfg.SMTP.Password, From: cfg.SMTP.From, StartTLS: cfg.SMTP.StartTLS}, logger)
	tokenRepo := account.NewPostgresTokenRepository(pool)
	recoveryRepo := account.NewPostgresRecoveryCodeRepository(pool)
	accountSvc := account.NewService(userRepo, tokenRepo, recoveryRepo, sessionRepo, passwords, encryptor, mail, auditRepo, cfg.OIDC.Issuer)
	authSvc := auth.NewService(userRepo, sessionRepo, auditRepo, passwords, tokens, cfg.Token.SessionTTL).WithLDAP(ldapAuth).WithLockout(loginAttempts).WithMFA(accountSvc, tokens)
	userSvc := users.NewService(userRepo, passwords, auditRepo).WithTokenCache(accessCache)
	bootstrapSvc := bootstrap.NewService(userRepo, passwords, rbacRepo, auditRepo)
	oauthRepo := oauth.NewPostgresRepository(pool, passwords)
	oauthSvc := oauth.NewService(oauthRepo, userRepo, sessionRepo, tokens, auditRepo, passwords).WithTokenVerifier(tokens).WithRefreshTTL(cfg.Token.RefreshTTL)
	accountSvc.WithRefreshRevoker(oauthRepo).WithTokenCache(accessCache)
	oidcKeys := oidc.NewPostgresKeyStore(pool)
	oidcSvc := oidc.NewService(cfg.OIDC.Issuer, oidcKeys)
	_ = oidcSvc.EnsureActiveKey(ctx)
	if cfg.OIDC.KeyRotationEnabled {
		oidcSvc.StartRotation(ctx, logger)
	}
	oauthSvc.WithIDTokenIssuer(oidcSvc).WithIDTokenVerifier(oidcSvc).WithBackchannel(oidcSvc)
	metrics := middleware.NewMetrics()
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP(cfg.HTTPSecurity.TrustedProxies))
	r.Use(metrics.Handler)
	r.Use(middleware.Recoverer(logger))
	r.Use(middleware.Logger(logger))
	r.Use(cors.Handler(cors.Options{AllowedOrigins: cfg.CORS.AllowedOrigins, AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}, AllowCredentials: true, MaxAge: 300}))
	r.Use(middleware.BodyLimit(1 << 20)) // 1 MiB cap on request bodies
	r.Use(middleware.RateLimit(middleware.NewTokenBucketLimiter(30, 10),
		"/api/v1/auth/login",
		"/api/v1/auth/mfa/verify",
		"/api/v1/auth/password/forgot",
		"/api/v1/auth/password/reset",
		"/api/v1/auth/email/verify",
		"/oauth2/token",
		"/oauth2/revoke",
		"/oauth2/introspect",
		"/api/v1/bootstrap"))
	r.Get("/metrics", metrics.Expose)
	health.RegisterRoutes(r, pool, version)
	require := func(resource, action string) func(http.Handler) http.Handler {
		return rbac.RequirePermission(rbacRepo, resource, action)
	}
	// One Bearer middleware for every protected router, sharing the access-state
	// cache so blocks and "sign out everywhere" are honoured consistently.
	bearer := auth.BearerAuth([]byte(cfg.Security.JWTSecret), accessCache)
	bootstrap.RegisterRoutes(r, bootstrapSvc)
	auth.RegisterRoutes(r, authSvc, userRepo, sessionRepo, []byte(cfg.Security.JWTSecret), accessCache)
	users.RegisterRoutes(r, userSvc, bearer, require)
	ldap.RegisterRoutes(r, ldapSvc, bearer, require)
	oauth.RegisterRoutes(r, oauthSvc, bearer, require)
	rbac.RegisterRoutes(r, rbacSvc, bearer, rbacRepo)
	audit.RegisterRoutes(r, auditRepo, bearer, require)
	account.RegisterRoutes(r, accountSvc, authSvc, bearer)
	brokerRepo := broker.NewPostgresRepository(pool, encryptor)
	brokerSvc := broker.NewService(brokerRepo, userRepo, authSvc, auditRepo, cfg.OIDC.Issuer, []byte(cfg.Security.JWTSecret))
	broker.RegisterRoutes(r, brokerSvc, bearer, require)
	startCleanup(ctx, pool, logger)
	registerSPA(r, logger)
	oidc.RegisterRoutes(r, oidcSvc, userRepo, bearer)
	return &App{pool: pool, router: r}, nil
}
func (a *App) Router() http.Handler { return a.router }
func (a *App) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}
