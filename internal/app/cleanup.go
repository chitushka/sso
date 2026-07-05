package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// startCleanup purges expired auth artifacts hourly so the tables do not grow
// without bound. Retention windows keep recent rows for audit/debugging.
func startCleanup(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	statements := []string{
		`DELETE FROM sessions WHERE expires_at < now() - interval '24 hours' OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '24 hours')`,
		`DELETE FROM oauth_authorization_codes WHERE expires_at < now() - interval '1 hour'`,
		`DELETE FROM refresh_tokens WHERE expires_at < now() - interval '7 days' OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')`,
		`DELETE FROM one_time_tokens WHERE expires_at < now() - interval '7 days' OR (used_at IS NOT NULL AND used_at < now() - interval '7 days')`,
		`DELETE FROM login_attempts WHERE updated_at < now() - interval '24 hours'`,
	}
	run := func() {
		for _, q := range statements {
			if _, err := pool.Exec(ctx, q); err != nil {
				logger.Warn("cleanup statement failed", "error", err)
			}
		}
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		run()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}
