package account

import (
	"context"
	"errors"
	"time"

	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresTokenRepository struct{ pool *pgxpool.Pool }

func NewPostgresTokenRepository(pool *pgxpool.Pool) *PostgresTokenRepository {
	return &PostgresTokenRepository{pool: pool}
}
func (r *PostgresTokenRepository) Create(ctx context.Context, userID uuid.UUID, purpose, tokenHash string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO one_time_tokens(user_id,purpose,token_hash,expires_at) VALUES($1,$2,$3,$4)`, userID, purpose, tokenHash, expiresAt)
	return err
}
func (r *PostgresTokenRepository) Consume(ctx context.Context, purpose, tokenHash string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := r.pool.QueryRow(ctx, `UPDATE one_time_tokens SET used_at=now() WHERE purpose=$1 AND token_hash=$2 AND used_at IS NULL AND expires_at>now() RETURNING user_id`, purpose, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, storage.ErrNotFound
	}
	return userID, err
}

type PostgresRecoveryCodeRepository struct{ pool *pgxpool.Pool }

func NewPostgresRecoveryCodeRepository(pool *pgxpool.Pool) *PostgresRecoveryCodeRepository {
	return &PostgresRecoveryCodeRepository{pool: pool}
}
func (r *PostgresRecoveryCodeRepository) Replace(ctx context.Context, userID uuid.UUID, codeHashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)`, userID, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (r *PostgresRecoveryCodeRepository) Consume(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at=now() WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL`, userID, codeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
func (r *PostgresRecoveryCodeRepository) DeleteAll(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=$1`, userID)
	return err
}
