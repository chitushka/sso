package users

import (
	"context"
	"errors"

	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Status, &u.Source, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, storage.ErrNotFound
	}
	return u, err
}
func (r *PostgresRepository) Create(ctx context.Context, u User) (User, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,status,source) VALUES($1,$2,$3,$4,$5) RETURNING id,username,email,password_hash,status,source,created_at,updated_at,last_login_at`, u.Username, u.Email, u.PasswordHash, u.Status, u.Source)
	created, err := scanUser(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return created, storage.ErrConflict
		}
		return created, err
	}
	return created, nil
}
func (r *PostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT id,username,email,password_hash,status,source,created_at,updated_at,last_login_at FROM users WHERE id=$1`, id))
}
func (r *PostgresRepository) FindByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT id,username,email,password_hash,status,source,created_at,updated_at,last_login_at FROM users WHERE username=$1`, username))
}
func (r *PostgresRepository) List(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,username,email,password_hash,status,source,created_at,updated_at,last_login_at FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) Update(ctx context.Context, u User) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `UPDATE users SET username=$2,email=$3,status=$4,updated_at=now() WHERE id=$1 RETURNING id,username,email,password_hash,status,source,created_at,updated_at,last_login_at`, u.ID, u.Username, u.Email, u.Status))
}
func (r *PostgresRepository) SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE users SET password_hash=$2,updated_at=now() WHERE id=$1`, id, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
func (r *PostgresRepository) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET last_login_at=now() WHERE id=$1`, id)
	return err
}

func (r *PostgresRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count)
	return count, err
}
