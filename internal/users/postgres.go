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

const userColumns = `id,username,email,COALESCE(password_hash,''),status,source,ldap_provider_id,ldap_dn,created_at,updated_at,last_login_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Status, &u.Source, &u.LDAPProviderID, &u.LDAPDN, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, storage.ErrNotFound
	}
	return u, err
}
func (r *PostgresRepository) Create(ctx context.Context, u User) (User, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,status,source,ldap_provider_id,ldap_dn) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+userColumns, u.Username, u.Email, nullableString(u.PasswordHash), u.Status, u.Source, u.LDAPProviderID, nullableString(u.LDAPDN))
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
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id=$1`, id))
}
func (r *PostgresRepository) FindByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE username=$1`, username))
}
func (r *PostgresRepository) FindByLDAPDN(ctx context.Context, providerID uuid.UUID, dn string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE ldap_provider_id=$1 AND ldap_dn=$2`, providerID, dn))
}
func (r *PostgresRepository) List(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
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
	return scanUser(r.pool.QueryRow(ctx, `UPDATE users SET username=$2,email=$3,status=$4,updated_at=now() WHERE id=$1 RETURNING `+userColumns, u.ID, u.Username, u.Email, u.Status))
}
func (r *PostgresRepository) SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	tag, err := r.pool.Exec(ctx, `UPDATE users SET password_hash=$2,updated_at=now(),source='local',ldap_provider_id=NULL,ldap_dn=NULL WHERE id=$1`, id, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
func (r *PostgresRepository) SyncLDAPUser(ctx context.Context, u User) (User, error) {
	if u.Status == "" {
		u.Status = StatusActive
	}
	if u.Source == "" {
		u.Source = SourceLDAP
	}
	row := r.pool.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,status,source,ldap_provider_id,ldap_dn)
		VALUES($1,$2,NULL,$3,$4,$5,$6)
		ON CONFLICT (username) DO UPDATE SET
			email=EXCLUDED.email,
			source=EXCLUDED.source,
			ldap_provider_id=EXCLUDED.ldap_provider_id,
			ldap_dn=EXCLUDED.ldap_dn,
			updated_at=now()
		RETURNING `+userColumns, u.Username, u.Email, u.Status, u.Source, u.LDAPProviderID, u.LDAPDN)
	return scanUser(row)
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

func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
