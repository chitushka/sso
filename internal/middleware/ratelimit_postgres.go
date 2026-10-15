package middleware

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresTokenBucketLimiter хранит общее состояние для всех экземпляров SSO.
// Ключ хешируется, чтобы IP-адрес и маршрут не сохранялись в открытом виде.
type PostgresTokenBucketLimiter struct {
	pool  *pgxpool.Pool
	rate  float64
	burst float64
	ttl   time.Duration
	calls atomic.Uint64
}

func NewPostgresTokenBucketLimiter(pool *pgxpool.Pool, ratePerMinute, burst int) *PostgresTokenBucketLimiter {
	if ratePerMinute <= 0 || burst <= 0 {
		panic("параметры rate limiter должны быть положительными")
	}
	rate := float64(ratePerMinute) / 60
	return &PostgresTokenBucketLimiter{
		pool:  pool,
		rate:  rate,
		burst: float64(burst),
		ttl:   time.Duration(float64(time.Second) * float64(burst) / rate),
	}
}

func (l *PostgresTokenBucketLimiter) Allow(ctx context.Context, key string) (bool, error) {
	digest := sha256.Sum256([]byte(key))
	now := time.Now()
	var allowed bool
	err := l.pool.QueryRow(ctx, `
		INSERT INTO rate_limit_buckets(key_hash,tokens,updated_at,expires_at)
		VALUES($1,$2-1,$4,$5)
		ON CONFLICT (key_hash) DO UPDATE SET
			tokens=LEAST($2,rate_limit_buckets.tokens+GREATEST(0,EXTRACT(EPOCH FROM ($4-rate_limit_buckets.updated_at)))*$3)-1,
			updated_at=$4,
			expires_at=$5
		WHERE LEAST($2,rate_limit_buckets.tokens+GREATEST(0,EXTRACT(EPOCH FROM ($4-rate_limit_buckets.updated_at)))*$3)>=1
		RETURNING true`, digest[:], l.burst, l.rate, now, now.Add(l.ttl)).Scan(&allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		l.cleanupExpired(ctx)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("shared rate limiter: %w", err)
	}
	l.cleanupExpired(ctx)
	return allowed, nil
}

func (l *PostgresTokenBucketLimiter) cleanupExpired(ctx context.Context) {
	if l.calls.Add(1)%1024 != 0 {
		return
	}
	_, _ = l.pool.Exec(ctx, `DELETE FROM rate_limit_buckets WHERE key_hash IN (
		SELECT key_hash FROM rate_limit_buckets WHERE expires_at < now() ORDER BY expires_at LIMIT 1000
	)`)
}
