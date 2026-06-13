package oidc

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresKeyStore struct{ pool *pgxpool.Pool }

func NewPostgresKeyStore(pool *pgxpool.Pool) *PostgresKeyStore { return &PostgresKeyStore{pool: pool} }
func scanKey(row pgx.Row) (SigningKey, error) {
	var k SigningKey
	err := row.Scan(&k.ID, &k.Kid, &k.Alg, &k.PrivateKeyPEM, &k.PublicKeyPEM, &k.Status, &k.CreatedAt, &k.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return k, storage.ErrNotFound
	}
	return k, err
}
func (s *PostgresKeyStore) ActiveKey(ctx context.Context) (SigningKey, error) {
	return scanKey(s.pool.QueryRow(ctx, `SELECT id,kid,alg,private_key_pem,public_key_pem,status,created_at,expires_at FROM oidc_signing_keys WHERE status='active' ORDER BY created_at DESC LIMIT 1`))
}
func (s *PostgresKeyStore) Create(ctx context.Context, k SigningKey) (SigningKey, error) {
	return scanKey(s.pool.QueryRow(ctx, `INSERT INTO oidc_signing_keys(kid,alg,private_key_pem,public_key_pem,status,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,kid,alg,private_key_pem,public_key_pem,status,created_at,expires_at`, k.Kid, k.Alg, k.PrivateKeyPEM, k.PublicKeyPEM, k.Status, k.ExpiresAt))
}
func (s *PostgresKeyStore) PublicKeys(ctx context.Context) ([]SigningKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,kid,alg,private_key_pem,public_key_pem,status,created_at,expires_at FROM oidc_signing_keys WHERE status IN ('active','retiring') ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SigningKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
