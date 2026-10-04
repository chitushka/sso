package secrets

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	databaseKeyLockID        int64 = 0x53534f454e434b
	databaseKeyVerifierPlain       = "sso-encryption-key-verifier:v1"
)

type secretColumn struct {
	name      string
	selectSQL string
	updateSQL string
}

var databaseSecretColumns = []secretColumn{
	{name: "LDAP bind passwords", selectSQL: `SELECT id,bind_password FROM ldap_providers WHERE bind_password <> '' FOR UPDATE`, updateSQL: `UPDATE ldap_providers SET bind_password=$2 WHERE id=$1`},
	{name: "OIDC signing keys", selectSQL: `SELECT id,private_key_pem FROM oidc_signing_keys WHERE private_key_pem <> '' FOR UPDATE`, updateSQL: `UPDATE oidc_signing_keys SET private_key_pem=$2 WHERE id=$1`},
	{name: "identity-provider client secrets", selectSQL: `SELECT id,client_secret FROM identity_providers WHERE client_secret <> '' FOR UPDATE`, updateSQL: `UPDATE identity_providers SET client_secret=$2 WHERE id=$1`},
	{name: "MFA secrets", selectSQL: `SELECT id,mfa_secret FROM users WHERE mfa_secret <> '' FOR UPDATE`, updateSQL: `UPDATE users SET mfa_secret=$2 WHERE id=$1`},
}

type secretMutation struct {
	column     secretColumn
	id         uuid.UUID
	plaintext  string
	ciphertext string
}

// EnsureDatabaseKey verifies at startup that the configured key can decrypt
// every encrypted data class. On first use it creates an encrypted verifier
// only after existing ciphertext has been checked.
func EnsureDatabaseKey(ctx context.Context, pool *pgxpool.Pool, encryptor Encryptor) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockDatabaseKey(ctx, tx); err != nil {
		return err
	}
	if err := verifyOrInitializeDatabaseKey(ctx, tx, encryptor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RotateDatabaseKey atomically re-encrypts every reversible database secret.
// Deployments must stop all API instances while this offline operation runs.
func RotateDatabaseKey(ctx context.Context, pool *pgxpool.Pool, oldEncryptor, newEncryptor Encryptor) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockDatabaseKey(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE encryption_key_metadata,ldap_providers,oidc_signing_keys,identity_providers,users IN ACCESS EXCLUSIVE MODE`); err != nil {
		return err
	}
	if err := verifyOrInitializeDatabaseKey(ctx, tx, oldEncryptor); err != nil {
		return fmt.Errorf("current encryption key verification failed: %w", err)
	}
	mutations, err := loadSecrets(ctx, tx, oldEncryptor)
	if err != nil {
		return err
	}
	for i := range mutations {
		mutations[i].ciphertext, err = newEncryptor.Encrypt(mutations[i].plaintext)
		if err != nil {
			return err
		}
	}
	verifier, err := newEncryptor.Encrypt(databaseKeyVerifierPlain)
	if err != nil {
		return err
	}
	for _, mutation := range mutations {
		if _, err := tx.Exec(ctx, mutation.column.updateSQL, mutation.id, mutation.ciphertext); err != nil {
			return fmt.Errorf("re-encrypt %s: %w", mutation.column.name, err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE encryption_key_metadata SET verifier=$1,updated_at=now() WHERE id=1`, verifier); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func lockDatabaseKey(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, databaseKeyLockID)
	return err
}

func verifyOrInitializeDatabaseKey(ctx context.Context, tx pgx.Tx, encryptor Encryptor) error {
	var verifier string
	err := tx.QueryRow(ctx, `SELECT verifier FROM encryption_key_metadata WHERE id=1 FOR UPDATE`).Scan(&verifier)
	if err == nil {
		plain, err := encryptor.Decrypt(verifier)
		if err != nil || subtle.ConstantTimeCompare([]byte(plain), []byte(databaseKeyVerifierPlain)) != 1 {
			return errors.New("configured encryption key does not match the database")
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err := loadSecrets(ctx, tx, encryptor); err != nil {
		return fmt.Errorf("validate existing encrypted data: %w", err)
	}
	verifier, err = encryptor.Encrypt(databaseKeyVerifierPlain)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO encryption_key_metadata(id,verifier) VALUES(1,$1)`, verifier)
	return err
}

func loadSecrets(ctx context.Context, tx pgx.Tx, encryptor Encryptor) ([]secretMutation, error) {
	var out []secretMutation
	for _, column := range databaseSecretColumns {
		rows, err := tx.Query(ctx, column.selectSQL)
		if err != nil {
			return nil, err
		}
		var encrypted []struct {
			id    uuid.UUID
			value string
		}
		for rows.Next() {
			var row struct {
				id    uuid.UUID
				value string
			}
			if err := rows.Scan(&row.id, &row.value); err != nil {
				rows.Close()
				return nil, err
			}
			encrypted = append(encrypted, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		for _, row := range encrypted {
			plain, err := encryptor.Decrypt(row.value)
			if err != nil {
				return nil, fmt.Errorf("decrypt %s: %w", column.name, err)
			}
			out = append(out, secretMutation{column: column, id: row.id, plaintext: plain})
		}
	}
	return out, nil
}
