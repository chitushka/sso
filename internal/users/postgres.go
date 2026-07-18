package users

import (
	"context"
	"errors"
	"time"

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
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Status, &u.Source, &u.FirstName, &u.LastName, &u.Attributes, &u.EmailVerified, &u.MFAEnabled, &u.MFASecret, &u.MFALastUsedCounter, &u.LDAPProviderID, &u.LDAPDN, &u.TokensInvalidBefore, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, storage.ErrNotFound
	}
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	return u, err
}

const userCols = "id,username,email,password_hash,status,source,first_name,last_name,attributes,email_verified,mfa_enabled,mfa_secret,mfa_last_used_counter,ldap_provider_id,ldap_dn,tokens_invalid_before,created_at,updated_at,last_login_at"

func (r *PostgresRepository) Create(ctx context.Context, u User) (User, error) {
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	row := r.pool.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,status,source,first_name,last_name,attributes,ldap_provider_id,ldap_dn) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+userCols, u.Username, u.Email, u.PasswordHash, u.Status, u.Source, u.FirstName, u.LastName, u.Attributes, u.LDAPProviderID, u.LDAPDN)
	x, err := scanUser(row)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return x, storage.ErrConflict
		}
		return x, err
	}
	return x, nil
}
func (r *PostgresRepository) UpsertLDAP(ctx context.Context, u User) (User, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,status,source,ldap_provider_id,ldap_dn) VALUES($1,$2,NULL,$3,'ldap',$4,$5) ON CONFLICT(username) DO UPDATE SET email=EXCLUDED.email, source='ldap', ldap_provider_id=EXCLUDED.ldap_provider_id, ldap_dn=EXCLUDED.ldap_dn, updated_at=now() RETURNING `+userCols, u.Username, u.Email, u.Status, u.LDAPProviderID, u.LDAPDN)
	return scanUser(row)
}
func (r *PostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}
func (r *PostgresRepository) FindByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username=$1`, username))
}
func (r *PostgresRepository) FindByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email=$1 ORDER BY created_at ASC LIMIT 1`, email))
}
func (r *PostgresRepository) List(ctx context.Context, limit, offset int) ([]User, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
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
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	return scanUser(r.pool.QueryRow(ctx, `UPDATE users SET username=$2,email=$3,status=$4,first_name=$5,last_name=$6,attributes=$7,updated_at=now() WHERE id=$1 RETURNING `+userCols, u.ID, u.Username, u.Email, u.Status, u.FirstName, u.LastName, u.Attributes))
}
func (r *PostgresRepository) SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET email_verified=$2,updated_at=now() WHERE id=$1`, id, verified)
	return err
}
func (r *PostgresRepository) SetMFA(ctx context.Context, id uuid.UUID, enabled bool, secret string) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET mfa_enabled=$2,mfa_secret=$3,updated_at=now() WHERE id=$1`, id, enabled, secret)
	return err
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

// InvalidateTokens revokes every access token already issued to the user by
// advancing tokens_invalid_before to now(); BearerAuth rejects older tokens.
func (r *PostgresRepository) InvalidateTokens(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET tokens_invalid_before=now(),updated_at=now() WHERE id=$1`, id)
	return err
}

// AccessState returns whether the account is still active and the cutoff before
// which its first-party access tokens are void, in one lookup for BearerAuth.
func (r *PostgresRepository) AccessState(ctx context.Context, id uuid.UUID) (bool, *time.Time, error) {
	var status Status
	var t *time.Time
	err := r.pool.QueryRow(ctx, `SELECT status, tokens_invalid_before FROM users WHERE id=$1`, id).Scan(&status, &t)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, storage.ErrNotFound
	}
	if err != nil {
		return false, nil, err
	}
	return status == StatusActive, t, nil
}

// SetMFACounter persists the last accepted TOTP time-step to block replay.
func (r *PostgresRepository) SetMFACounter(ctx context.Context, id uuid.UUID, counter int64) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET mfa_last_used_counter=$2 WHERE id=$1`, id, counter)
	return err
}
func (r *PostgresRepository) Count(ctx context.Context) (int64, error) {
	var c int64
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&c)
	return c, err
}
