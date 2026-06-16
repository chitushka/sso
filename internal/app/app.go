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
	ldapRepo := ldap.NewPostgresRepository(pool)
	ldapClient := ldap.NewClient()
	ldapSvc := ldap.NewService(ldapRepo, ldapClient, auditRepo)
	ldapAuth := ldap.NewAuthenticator(ldapRepo, ldapClient, userRepo, auditRepo)
	authSvc := auth.NewService(userRepo, sessionRepo, auditRepo, passwords, tokens, cfg.Token.SessionTTL).WithLDAP(ldapAuth)
	userSvc := users.NewService(userRepo, passwords, auditRepo)
	bootstrapSvc := bootstrap.NewService(userRepo, passwords, rbacRepo, auditRepo)
	oauthRepo := oauth.NewPostgresRepository(pool, passwords)
	oauthSvc := oauth.NewService(oauthRepo, userRepo, sessionRepo, tokens, auditRepo)
	oidcKeys := oidc.NewPostgresKeyStore(pool)
	oidcSvc := oidc.NewService(cfg.OIDC.Issuer, oidcKeys)
	_ = oidcSvc.EnsureActiveKey(ctx)
	oauthSvc.WithIDTokenIssuer(oidcSvc)
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer(logger))
	r.Use(middleware.Logger(logger))
	r.Use(cors.Handler(cors.Options{AllowedOrigins: cfg.CORS.AllowedOrigins, AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}, AllowCredentials: true, MaxAge: 300}))
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
	oidc.RegisterRoutes(r, oidcSvc, userRepo, auth.BearerAuth([]byte(cfg.Security.JWTSecret)))
	return &App{pool: pool, router: r}, nil
}
func (a *App) Router() http.Handler { return a.router }
func (a *App) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}
