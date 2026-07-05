package auth

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresSessionRepository struct{ pool *pgxpool.Pool }

func NewPostgresSessionRepository(pool *pgxpool.Pool) *PostgresSessionRepository {
	return &PostgresSessionRepository{pool: pool}
}
func (r *PostgresSessionRepository) Create(ctx context.Context, s Session) (Session, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO sessions(user_id,token_hash,ip,user_agent,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING id,user_id,token_hash,ip,user_agent,expires_at,revoked_at`, s.UserID, s.TokenHash, s.IP, s.UserAgent, s.ExpiresAt)
	err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IP, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt)
	return s, err
}
func (r *PostgresSessionRepository) FindByTokenHash(ctx context.Context, hash string) (Session, error) {
	var s Session
	err := r.pool.QueryRow(ctx, `SELECT id,user_id,token_hash,ip,user_agent,expires_at,revoked_at FROM sessions WHERE token_hash=$1`, hash).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IP, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, storage.ErrNotFound
	}
	return s, err
}
func (r *PostgresSessionRepository) RevokeByTokenHash(ctx context.Context, hash string) error {
	_, err := r.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE token_hash=$1`, hash)
	return err
}
func (r *PostgresSessionRepository) RevokeAllByUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, userID)
	return err
}
func (r *PostgresSessionRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,user_id,token_hash,ip,user_agent,expires_at,revoked_at,created_at FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IP, &s.UserAgent, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
func (r *PostgresSessionRepository) RevokeByID(ctx context.Context, userID, sessionID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL`, sessionID, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return err
}
