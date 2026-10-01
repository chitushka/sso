package account

import (
	"context"
	"errors"

	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (r *PostgresTokenRepository) ResetPassword(ctx context.Context, tokenHash, passwordHash string) (uuid.UUID, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE one_time_tokens SET used_at=now()
		WHERE purpose=$1 AND token_hash=$2 AND used_at IS NULL AND expires_at>now()
		RETURNING user_id`, PurposePasswordReset, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, storage.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if err = replacePasswordAndRevoke(ctx, tx, userID, "", passwordHash); err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

func (r *PostgresTokenRepository) ChangePassword(ctx context.Context, userID uuid.UUID, currentHash, newHash string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = replacePasswordAndRevoke(ctx, tx, userID, currentHash, newHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func replacePasswordAndRevoke(ctx context.Context, tx pgx.Tx, userID uuid.UUID, currentHash, newHash string) error {
	query := `UPDATE users SET password_hash=$2,tokens_invalid_before=now(),updated_at=now() WHERE id=$1`
	args := []any{userID, newHash}
	if currentHash != "" {
		query += ` AND password_hash=$3`
		args = append(args, currentHash)
	}
	tag, err := tx.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return storage.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}

func (r *PostgresTokenRepository) VerifyEmail(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE one_time_tokens SET used_at=now()
		WHERE purpose=$1 AND token_hash=$2 AND used_at IS NULL AND expires_at>now()
		RETURNING user_id`, PurposeEmailVerify, tokenHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, storage.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	tag, err := tx.Exec(ctx, `UPDATE users SET email_verified=true,
		status=CASE WHEN status='pending' THEN 'active' ELSE status END,updated_at=now() WHERE id=$1`, userID)
	if err != nil {
		return uuid.Nil, err
	}
	if tag.RowsAffected() != 1 {
		return uuid.Nil, storage.ErrNotFound
	}
	return userID, tx.Commit(ctx)
}

func (r *PostgresTokenRepository) ActivateMFA(ctx context.Context, userID uuid.UUID, encryptedSecret string, codeHashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE users SET mfa_enabled=true,updated_at=now()
		WHERE id=$1 AND mfa_enabled=false AND mfa_secret=$2`, userID, encryptedSecret)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMFAState
	}
	if _, err = tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return err
	}
	for _, hash := range codeHashes {
		if _, err = tx.Exec(ctx, `INSERT INTO mfa_recovery_codes(user_id,code_hash) VALUES($1,$2)`, userID, hash); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
