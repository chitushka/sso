package bootstrap

import (
	"context"
	"errors"

	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AtomicRepository interface {
	CreateFirstAdmin(ctx context.Context, username, email, passwordHash string) (users.User, error)
}

type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) CreateFirstAdmin(ctx context.Context, username, email, passwordHash string) (users.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return users.User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1936941427)`); err != nil {
		return users.User{}, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return users.User{}, err
	}
	if exists {
		return users.User{}, ErrAlreadyInitialized
	}
	var u users.User
	err = tx.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,status,source)
		VALUES($1,$2,$3,'active','local')
		RETURNING id,username,email,password_hash,status,source,created_at,updated_at`,
		username, email, passwordHash).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Status, &u.Source, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return users.User{}, storage.ErrConflict
		}
		return users.User{}, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE code='admin'`, u.ID)
	if err != nil {
		return users.User{}, err
	}
	if tag.RowsAffected() != 1 {
		return users.User{}, errors.New("admin role is missing")
	}
	return u, tx.Commit(ctx)
}
