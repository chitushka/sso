package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chitushka/sso/internal/app"
	"github.com/chitushka/sso/internal/config"
	"github.com/chitushka/sso/internal/dbmigrate"
	"github.com/chitushka/sso/internal/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		if len(os.Args) == 2 && os.Args[1] == "rotate-encryption-key" {
			os.Exit(runEncryptionKeyRotation())
		}
		newLogger(os.Getenv("SSO_LOG_LEVEL")).Error("unknown command")
		os.Exit(2)
	}
	cfg, err := config.Load()
	logger := newLogger(cfg.Logging.Level)
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	a, err := app.New(ctx, cfg, logger, version)
	if err != nil {
		logger.Error("init app", "error", err)
		os.Exit(1)
	}
	defer a.Close()

	srv := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           a.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		logger.Info("sso api started", "addr", cfg.HTTP.Address, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server", "error", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	stopSignals()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func runEncryptionKeyRotation() int {
	logger := newLogger(os.Getenv("SSO_LOG_LEVEL"))
	databaseURL := strings.TrimSpace(os.Getenv("SSO_DATABASE_URL"))
	oldKey := os.Getenv("SSO_ENCRYPTION_KEY")
	newKey := os.Getenv("SSO_NEW_ENCRYPTION_KEY")
	if databaseURL == "" || len(oldKey) < 32 || len(newKey) < 32 || oldKey == newKey {
		logger.Error("rotation configuration", "error", "SSO_DATABASE_URL and two distinct encryption keys of at least 32 characters are required")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		logger.Error("connect database", "error", err)
		return 1
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		logger.Error("connect database", "error", err)
		return 1
	}
	if err := dbmigrate.CheckSchema(ctx, pool); err != nil {
		logger.Error("database schema is not current", "error", err)
		return 1
	}
	if err := secrets.RotateDatabaseKey(ctx, pool, secrets.NewAESGCM(oldKey), secrets.NewAESGCM(newKey)); err != nil {
		logger.Error("rotate database encryption key", "error", err)
		return 1
	}
	logger.Info("database encryption key rotated; replace SSO_ENCRYPTION_KEY before restarting the API")
	return 0
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel}))
}
