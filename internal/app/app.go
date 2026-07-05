package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/bootstrap"
	"github.com/chitushka/sso/internal/config"
	"github.com/chitushka/sso/internal/health"
	"github.com/chitushka/sso/internal/ldap"
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

func New(ctx context.Context, cfg config.Config, logger *slog.Logger) (*App, error) {
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	userRepo := users.NewPostgresRepository(pool)
	sessionRepo := auth.NewPostgresSessionRepository(pool)
	auditRepo := audit.NewPostgresRepository(pool)
	rbacRepo := rbac.NewPostgresRepository(pool)
	rbacSvc := rbac.NewService(rbacRepo, auditRepo)
	passwords := auth.NewArgon2idHasher()
	tokens := auth.NewJWTIssuer([]byte(cfg.Security.JWTSecret), cfg.Token.AccessTTL)
	encryptor := secrets.NewAESGCM(cfg.Security.EncryptionKey)
	ldapRepo := ldap.NewPostgresRepository(pool, encryptor)
	ldapClient := ldap.NewClient()
	ldapSvc := ldap.NewService(ldapRepo, ldapClient, auditRepo)
	ldapAuth := ldap.NewAuthenticator(ldapRepo, ldapClient, userRepo, auditRepo)
	loginAttempts := auth.NewPostgresLoginAttemptRepository(pool)
	authSvc := auth.NewService(userRepo, sessionRepo, auditRepo, passwords, tokens, cfg.Token.SessionTTL).WithLDAP(ldapAuth).WithLockout(loginAttempts)
	userSvc := users.NewService(userRepo, passwords, auditRepo)
	bootstrapSvc := bootstrap.NewService(userRepo, passwords, rbacRepo, auditRepo)
	oauthRepo := oauth.NewPostgresRepository(pool, passwords)
	oauthSvc := oauth.NewService(oauthRepo, userRepo, sessionRepo, tokens, auditRepo, passwords).WithTokenVerifier(tokens).WithRefreshTTL(cfg.Token.RefreshTTL)
	oidcKeys := oidc.NewPostgresKeyStore(pool)
	oidcSvc := oidc.NewService(cfg.OIDC.Issuer, oidcKeys)
	_ = oidcSvc.EnsureActiveKey(ctx)
	if cfg.OIDC.KeyRotationEnabled {
		oidcSvc.StartRotation(ctx, logger)
	}
	oauthSvc.WithIDTokenIssuer(oidcSvc).WithIDTokenVerifier(oidcSvc).WithBackchannel(oidcSvc)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer(logger))
	r.Use(middleware.Logger(logger))
	r.Use(cors.Handler(cors.Options{AllowedOrigins: cfg.CORS.AllowedOrigins, AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}, AllowCredentials: true, MaxAge: 300}))
	r.Use(middleware.RateLimit(middleware.NewTokenBucketLimiter(30, 10), "/api/v1/auth/login", "/oauth2/token", "/api/v1/bootstrap"))
	health.RegisterRoutes(r, pool)
	require := func(resource, action string) func(http.Handler) http.Handler {
		return rbac.RequirePermission(rbacRepo, resource, action)
	}
	bootstrap.RegisterRoutes(r, bootstrapSvc)
	auth.RegisterRoutes(r, authSvc, userRepo, []byte(cfg.Security.JWTSecret))
	users.RegisterRoutes(r, userSvc, auth.BearerAuth([]byte(cfg.Security.JWTSecret)), require)
	ldap.RegisterRoutes(r, ldapSvc, auth.BearerAuth([]byte(cfg.Security.JWTSecret)), require)
	oauth.RegisterRoutes(r, oauthSvc, auth.BearerAuth([]byte(cfg.Security.JWTSecret)), require)
	rbac.RegisterRoutes(r, rbacSvc, auth.BearerAuth([]byte(cfg.Security.JWTSecret)), rbacRepo)
	audit.RegisterRoutes(r, auditRepo, auth.BearerAuth([]byte(cfg.Security.JWTSecret)), require)
	registerSPA(r, logger)
	oidc.RegisterRoutes(r, oidcSvc, userRepo, auth.BearerAuth([]byte(cfg.Security.JWTSecret)))
	return &App{pool: pool, router: r}, nil
}
func (a *App) Router() http.Handler { return a.router }
func (a *App) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}
