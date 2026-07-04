package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresLoginAttemptRepository struct{ pool *pgxpool.Pool }

func NewPostgresLoginAttemptRepository(pool *pgxpool.Pool) *PostgresLoginAttemptRepository {
	return &PostgresLoginAttemptRepository{pool: pool}
}
func (r *PostgresLoginAttemptRepository) Status(ctx context.Context, username, ip string) (LoginAttemptStatus, error) {
	var s LoginAttemptStatus
	err := r.pool.QueryRow(ctx, `SELECT attempts, locked_until FROM login_attempts WHERE username=$1 AND ip=$2 AND updated_at > now() - interval '1 hour'`, username, ip).Scan(&s.Attempts, &s.LockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginAttemptStatus{}, nil
	}
	return s, err
}
func (r *PostgresLoginAttemptRepository) Fail(ctx context.Context, username, ip string) (int, error) {
	var attempts int
	err := r.pool.QueryRow(ctx, `INSERT INTO login_attempts(username, ip, attempts) VALUES($1,$2,1)
ON CONFLICT (username, ip) DO UPDATE SET
    attempts = CASE WHEN login_attempts.updated_at < now() - interval '1 hour' THEN 1 ELSE login_attempts.attempts + 1 END,
    locked_until = CASE WHEN login_attempts.updated_at < now() - interval '1 hour' THEN NULL ELSE login_attempts.locked_until END,
    updated_at = now()
RETURNING attempts`, username, ip).Scan(&attempts)
	return attempts, err
}
func (r *PostgresLoginAttemptRepository) Lock(ctx context.Context, username, ip string, until time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE login_attempts SET locked_until=$3, updated_at=now() WHERE username=$1 AND ip=$2`, username, ip, until)
	return err
}
func (r *PostgresLoginAttemptRepository) Reset(ctx context.Context, username, ip string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM login_attempts WHERE username=$1 AND ip=$2`, username, ip)
	return err
}
