package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/chitushka/sso/internal/audit"
	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/config"
	"github.com/chitushka/sso/internal/health"
	"github.com/chitushka/sso/internal/ldap"
	"github.com/chitushka/sso/internal/middleware"
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
	pool, err := pgxpool.New(ctx, cfg.DB.URL)
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
	ldapRepo := ldap.NewPostgresRepository(pool)
	ldapSvc := ldap.NewService(ldapRepo, ldap.NewClient(), auditRepo)
	passwords := auth.NewArgon2idHasher()
	tokens := auth.NewJWTIssuer([]byte(cfg.Auth.JWTSecret), cfg.Auth.AccessTokenTTL)
	authSvc := auth.NewService(userRepo, sessionRepo, auditRepo, passwords, tokens, ldapSvc, cfg.Auth.SessionTTL)
	userSvc := users.NewService(userRepo, passwords, auditRepo)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer(logger))
	r.Use(middleware.Logger(logger))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORS.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	bearerAuth := auth.BearerAuth([]byte(cfg.Auth.JWTSecret))
	health.RegisterRoutes(r, pool)
	auth.RegisterRoutes(r, authSvc, userRepo, []byte(cfg.Auth.JWTSecret))
	users.RegisterRoutes(r, userSvc, bearerAuth)
	ldap.RegisterRoutes(r, ldapSvc, bearerAuth)

	return &App{pool: pool, router: r}, nil
}
func (a *App) Router() http.Handler { return a.router }
func (a *App) Close() {
	if a.pool != nil {
		a.pool.Close()
	}
}
