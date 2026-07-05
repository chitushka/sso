package broker

import (
	"context"
	"errors"

	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool      *pgxpool.Pool
	encryptor secrets.Encryptor
}

func NewPostgresRepository(pool *pgxpool.Pool, encryptor secrets.Encryptor) *PostgresRepository {
	return &PostgresRepository{pool: pool, encryptor: encryptor}
}

const providerCols = "id,code,name,type,client_id,client_secret,authorize_url,token_url,userinfo_url,scopes,enabled,created_at,updated_at"

func (r *PostgresRepository) scanProvider(row pgx.Row) (Provider, error) {
	var p Provider
	err := row.Scan(&p.ID, &p.Code, &p.Name, &p.Type, &p.ClientID, &p.ClientSecret, &p.AuthorizeURL, &p.TokenURL, &p.UserinfoURL, &p.Scopes, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, storage.ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.ClientSecret, err = r.encryptor.Decrypt(p.ClientSecret)
	return p, err
}
func (r *PostgresRepository) List(ctx context.Context) ([]Provider, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+providerCols+` FROM identity_providers ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		p, err := r.scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) FindByCode(ctx context.Context, code string) (Provider, error) {
	return r.scanProvider(r.pool.QueryRow(ctx, `SELECT `+providerCols+` FROM identity_providers WHERE code=$1`, code))
}
func (r *PostgresRepository) Create(ctx context.Context, p Provider) (Provider, error) {
	enc, err := r.encryptor.Encrypt(p.ClientSecret)
	if err != nil {
		return Provider{}, err
	}
	out, err := r.scanProvider(r.pool.QueryRow(ctx, `INSERT INTO identity_providers(code,name,type,client_id,client_secret,authorize_url,token_url,userinfo_url,scopes,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+providerCols, p.Code, p.Name, p.Type, p.ClientID, enc, p.AuthorizeURL, p.TokenURL, p.UserinfoURL, p.Scopes, p.Enabled))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return out, storage.ErrConflict
		}
	}
	return out, err
}
func (r *PostgresRepository) Update(ctx context.Context, p Provider) (Provider, error) {
	// An empty secret keeps the stored one, mirroring the LDAP provider UX.
	if p.ClientSecret == "" {
		current, err := r.scanProvider(r.pool.QueryRow(ctx, `SELECT `+providerCols+` FROM identity_providers WHERE id=$1`, p.ID))
		if err != nil {
			return Provider{}, err
		}
		p.ClientSecret = current.ClientSecret
	}
	enc, err := r.encryptor.Encrypt(p.ClientSecret)
	if err != nil {
		return Provider{}, err
	}
	return r.scanProvider(r.pool.QueryRow(ctx, `UPDATE identity_providers SET name=$2,type=$3,client_id=$4,client_secret=$5,authorize_url=$6,token_url=$7,userinfo_url=$8,scopes=$9,enabled=$10,updated_at=now() WHERE id=$1 RETURNING `+providerCols, p.ID, p.Name, p.Type, p.ClientID, enc, p.AuthorizeURL, p.TokenURL, p.UserinfoURL, p.Scopes, p.Enabled))
}
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM identity_providers WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return err
}
func (r *PostgresRepository) FindIdentity(ctx context.Context, providerID uuid.UUID, subject string) (FederatedIdentity, error) {
	var fi FederatedIdentity
	err := r.pool.QueryRow(ctx, `SELECT provider_id,external_subject,user_id,email,created_at FROM federated_identities WHERE provider_id=$1 AND external_subject=$2`, providerID, subject).Scan(&fi.ProviderID, &fi.ExternalSubject, &fi.UserID, &fi.Email, &fi.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return fi, storage.ErrNotFound
	}
	return fi, err
}
func (r *PostgresRepository) LinkIdentity(ctx context.Context, fi FederatedIdentity) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO federated_identities(provider_id,external_subject,user_id,email) VALUES($1,$2,$3,$4) ON CONFLICT (provider_id,external_subject) DO NOTHING`, fi.ProviderID, fi.ExternalSubject, fi.UserID, fi.Email)
	return err
}
