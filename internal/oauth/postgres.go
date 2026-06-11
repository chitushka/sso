package oauth

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

func scanClient(row pgx.Row) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.Type, &c.RedirectURIs, &c.AllowedScopes, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, storage.ErrNotFound
	}
	return c, err
}

func (r *PostgresRepository) CreateClient(ctx context.Context, c Client) (Client, error) {
	created, err := scanClient(r.pool.QueryRow(ctx, `INSERT INTO oauth_clients(client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled,created_at,updated_at`, c.ClientID, c.ClientSecretHash, c.Name, c.Type, c.RedirectURIs, c.AllowedScopes, c.Enabled))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return created, storage.ErrConflict
		}
		return created, err
	}
	return created, nil
}

func (r *PostgresRepository) FindClientByID(ctx context.Context, id uuid.UUID) (Client, error) {
	return scanClient(r.pool.QueryRow(ctx, `SELECT id,client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled,created_at,updated_at FROM oauth_clients WHERE id=$1`, id))
}

func (r *PostgresRepository) FindClientByClientID(ctx context.Context, clientID string) (Client, error) {
	return scanClient(r.pool.QueryRow(ctx, `SELECT id,client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled,created_at,updated_at FROM oauth_clients WHERE client_id=$1`, clientID))
}

func (r *PostgresRepository) ListClients(ctx context.Context, limit, offset int) ([]Client, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled,created_at,updated_at FROM oauth_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) UpdateClient(ctx context.Context, c Client) (Client, error) {
	return scanClient(r.pool.QueryRow(ctx, `UPDATE oauth_clients SET name=$2,type=$3,redirect_uris=$4,allowed_scopes=$5,enabled=$6,updated_at=now() WHERE id=$1 RETURNING id,client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled,created_at,updated_at`, c.ID, c.Name, c.Type, c.RedirectURIs, c.AllowedScopes, c.Enabled))
}

func (r *PostgresRepository) DeleteClient(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAuthorizationCode(row pgx.Row) (AuthorizationCode, error) {
	var code AuthorizationCode
	err := row.Scan(&code.ID, &code.CodeHash, &code.ClientID, &code.UserID, &code.RedirectURI, &code.Scope, &code.CodeChallenge, &code.CodeChallengeMethod, &code.ExpiresAt, &code.UsedAt, &code.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return code, storage.ErrNotFound
	}
	return code, err
}

func (r *PostgresRepository) CreateAuthorizationCode(ctx context.Context, code AuthorizationCode) (AuthorizationCode, error) {
	return scanAuthorizationCode(r.pool.QueryRow(ctx, `INSERT INTO oauth_authorization_codes(code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at,used_at,created_at`, code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope, code.CodeChallenge, code.CodeChallengeMethod, code.ExpiresAt))
}

func (r *PostgresRepository) FindAuthorizationCodeByHash(ctx context.Context, codeHash string) (AuthorizationCode, error) {
	return scanAuthorizationCode(r.pool.QueryRow(ctx, `SELECT id,code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,expires_at,used_at,created_at FROM oauth_authorization_codes WHERE code_hash=$1`, codeHash))
}

func (r *PostgresRepository) MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `UPDATE oauth_authorization_codes SET used_at=now() WHERE id=$1 AND used_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
