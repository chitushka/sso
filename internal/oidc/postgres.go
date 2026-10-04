package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresKeyStore struct {
	pool      *pgxpool.Pool
	encryptor secrets.Encryptor
}

func NewPostgresKeyStore(pool *pgxpool.Pool, encryptor secrets.Encryptor) *PostgresKeyStore {
	return &PostgresKeyStore{pool: pool, encryptor: encryptor}
}
func (s *PostgresKeyStore) scanKey(row pgx.Row) (SigningKey, error) {
	var k SigningKey
	err := row.Scan(&k.ID, &k.Kid, &k.Alg, &k.PrivateKeyPEM, &k.PublicKeyPEM, &k.Status, &k.CreatedAt, &k.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return k, storage.ErrNotFound
	}
	if err != nil {
		return k, err
	}
	if k.PrivateKeyPEM != "" {
		k.PrivateKeyPEM, err = s.encryptor.Decrypt(k.PrivateKeyPEM)
	}
	return k, err
}
func (s *PostgresKeyStore) ActiveKey(ctx context.Context) (SigningKey, error) {
	return s.scanKey(s.pool.QueryRow(ctx, `SELECT id,kid,alg,private_key_pem,public_key_pem,status,created_at,expires_at FROM oidc_signing_keys WHERE status='active' ORDER BY created_at DESC LIMIT 1`))
}
func (s *PostgresKeyStore) encryptKey(k SigningKey) (SigningKey, error) {
	encrypted, err := s.encryptor.Encrypt(k.PrivateKeyPEM)
	if err != nil {
		return SigningKey{}, err
	}
	k.PrivateKeyPEM = encrypted
	return k, nil
}

const keyRotationLockID int64 = 0x53534f4b455953

func (s *PostgresKeyStore) EnsureActive(ctx context.Context, candidate SigningKey) (SigningKey, error) {
	candidate, err := s.encryptKey(candidate)
	if err != nil {
		return SigningKey{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return SigningKey{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, keyRotationLockID); err != nil {
		return SigningKey{}, err
	}
	active, err := s.scanKey(tx.QueryRow(ctx, `SELECT id,kid,alg,private_key_pem,public_key_pem,status,created_at,expires_at FROM oidc_signing_keys WHERE status='active' LIMIT 1 FOR UPDATE`))
	if err == nil {
		return active, tx.Commit(ctx)
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return SigningKey{}, err
	}
	created, err := s.scanKey(tx.QueryRow(ctx, `INSERT INTO oidc_signing_keys(kid,alg,private_key_pem,public_key_pem,status,expires_at) VALUES($1,$2,$3,$4,'active',NULL) RETURNING id,kid,alg,private_key_pem,public_key_pem,status,created_at,expires_at`, candidate.Kid, candidate.Alg, candidate.PrivateKeyPEM, candidate.PublicKeyPEM))
	if err != nil {
		return SigningKey{}, err
	}
	return created, tx.Commit(ctx)
}

// Rotate changes the old key to retiring and inserts the replacement in one
// transaction. The advisory lock serializes rotation across application
// instances; a stale contender becomes a no-op after observing a newer key.
func (s *PostgresKeyStore) Rotate(ctx context.Context, currentID uuid.UUID, candidate SigningKey, retiringExpiresAt time.Time) error {
	candidate, err := s.encryptKey(candidate)
	if err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, keyRotationLockID); err != nil {
		return err
	}
	var activeID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM oidc_signing_keys WHERE status='active' LIMIT 1 FOR UPDATE`).Scan(&activeID)
	if errors.Is(err, pgx.ErrNoRows) {
		_, err = tx.Exec(ctx, `INSERT INTO oidc_signing_keys(kid,alg,private_key_pem,public_key_pem,status) VALUES($1,$2,$3,$4,'active')`, candidate.Kid, candidate.Alg, candidate.PrivateKeyPEM, candidate.PublicKeyPEM)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if activeID != currentID {
		return tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `UPDATE oidc_signing_keys SET status='retiring', expires_at=$2 WHERE id=$1 AND status='active'`, currentID, retiringExpiresAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO oidc_signing_keys(kid,alg,private_key_pem,public_key_pem,status) VALUES($1,$2,$3,$4,'active')`, candidate.Kid, candidate.Alg, candidate.PrivateKeyPEM, candidate.PublicKeyPEM); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *PostgresKeyStore) RetireExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE oidc_signing_keys SET status='retired' WHERE status='retiring' AND expires_at IS NOT NULL AND expires_at < now()`)
	return err
}
func (s *PostgresKeyStore) PublicKeys(ctx context.Context) ([]SigningKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,kid,alg,'' AS private_key_pem,public_key_pem,status,created_at,expires_at FROM oidc_signing_keys WHERE status IN ('active','retiring') ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SigningKey{}
	for rows.Next() {
		k, err := s.scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
