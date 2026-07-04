package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/chitushka/sso/internal/auth"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool   *pgxpool.Pool
	hasher auth.PasswordHasher
}

func NewPostgresRepository(pool *pgxpool.Pool, hasher auth.PasswordHasher) *PostgresRepository {
	return &PostgresRepository{pool: pool, hasher: hasher}
}
func scanClient(row pgx.Row) (Client, error) {
	var c Client
	err := row.Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.Type, &c.RedirectURIs, &c.AllowedScopes, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, storage.ErrNotFound
	}
	return c, err
}

const clientCols = "id,client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled,created_at,updated_at"

func secret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (r *PostgresRepository) CreateClient(ctx context.Context, c Client) (Client, string, error) {
	raw := ""
	var hash *string
	if c.Type == ClientConfidential {
		s, err := secret()
		if err != nil {
			return c, "", err
		}
		h, err := r.hasher.Hash(s)
		if err != nil {
			return c, "", err
		}
		raw = s
		hash = &h
	}
	row := r.pool.QueryRow(ctx, `INSERT INTO oauth_clients(client_id,client_secret_hash,name,type,redirect_uris,allowed_scopes,enabled) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING `+clientCols, c.ClientID, hash, c.Name, c.Type, c.RedirectURIs, c.AllowedScopes, c.Enabled)
	out, err := scanClient(row)
	return out, raw, err
}
func (r *PostgresRepository) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+clientCols+` FROM oauth_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) FindClientByClientID(ctx context.Context, clientID string) (Client, error) {
	return scanClient(r.pool.QueryRow(ctx, `SELECT `+clientCols+` FROM oauth_clients WHERE client_id=$1`, clientID))
}
func (r *PostgresRepository) UpdateClient(ctx context.Context, c Client) (Client, error) {
	return scanClient(r.pool.QueryRow(ctx, `UPDATE oauth_clients SET name=$2,redirect_uris=$3,allowed_scopes=$4,enabled=$5,updated_at=now() WHERE id=$1 RETURNING `+clientCols, c.ID, c.Name, c.RedirectURIs, c.AllowedScopes, c.Enabled))
}
func (r *PostgresRepository) DeleteClient(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return err
}

const refreshCols = "id,token_hash,family_id,user_id,client_id,scope,expires_at,rotated_at,revoked_at,created_at"

func scanRefreshToken(row pgx.Row) (RefreshToken, error) {
	var t RefreshToken
	err := row.Scan(&t.ID, &t.TokenHash, &t.FamilyID, &t.UserID, &t.ClientID, &t.Scope, &t.ExpiresAt, &t.RotatedAt, &t.RevokedAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, storage.ErrNotFound
	}
	return t, err
}
func (r *PostgresRepository) CreateRefreshToken(ctx context.Context, t RefreshToken) (RefreshToken, error) {
	return scanRefreshToken(r.pool.QueryRow(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,user_id,client_id,scope,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING `+refreshCols, t.TokenHash, t.FamilyID, t.UserID, t.ClientID, t.Scope, t.ExpiresAt))
}
func (r *PostgresRepository) FindRefreshTokenByHash(ctx context.Context, hash string) (RefreshToken, error) {
	return scanRefreshToken(r.pool.QueryRow(ctx, `SELECT `+refreshCols+` FROM refresh_tokens WHERE token_hash=$1`, hash))
}
func (r *PostgresRepository) MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE refresh_tokens SET rotated_at=now() WHERE id=$1`, id)
	return err
}
func (r *PostgresRepository) RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL`, familyID)
	return err
}
func (r *PostgresRepository) CreateCode(ctx context.Context, c AuthorizationCode) (AuthorizationCode, error) {
	err := r.pool.QueryRow(ctx, `INSERT INTO oauth_authorization_codes(code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,nonce,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,created_at`, c.CodeHash, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.CodeChallenge, c.CodeChallengeMethod, c.Nonce, c.ExpiresAt).Scan(&c.ID, &c.CreatedAt)
	return c, err
}
func (r *PostgresRepository) ConsumeCode(ctx context.Context, hash string) (AuthorizationCode, error) {
	var c AuthorizationCode
	err := r.pool.QueryRow(ctx, `UPDATE oauth_authorization_codes SET used_at=now() WHERE code_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING id,code_hash,client_id,user_id,redirect_uri,scope,code_challenge,code_challenge_method,nonce,expires_at,created_at,used_at`, hash).Scan(&c.ID, &c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &c.ExpiresAt, &c.CreatedAt, &c.UsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, storage.ErrNotFound
	}
	return c, err
}
