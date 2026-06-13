package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chitushka/sso/internal/app"
	"github.com/chitushka/sso/internal/config"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}
	ctx := context.Background()
	a, err := app.New(ctx, cfg, logger)
	if err != nil {
		logger.Error("init app", "error", err)
		os.Exit(1)
	}
	defer a.Close()

	srv := &http.Server{Addr: cfg.HTTP.Addr, Handler: a.Router(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("sso api started", "addr", cfg.HTTP.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server", "error", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
