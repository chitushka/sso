package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/storage"
	"github.com/chitushka/sso/internal/users"
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
const brokerUserCols = "id,username,email,password_hash,status,source,first_name,last_name,attributes,email_verified,mfa_enabled,mfa_secret,mfa_last_used_counter,ldap_provider_id,ldap_dn,tokens_invalid_before,created_at,updated_at,last_login_at"

func scanResolvedUser(row pgx.Row) (users.User, error) {
	var u users.User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Status, &u.Source,
		&u.FirstName, &u.LastName, &u.Attributes, &u.EmailVerified, &u.MFAEnabled,
		&u.MFASecret, &u.MFALastUsedCounter, &u.LDAPProviderID, &u.LDAPDN,
		&u.TokensInvalidBefore, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, storage.ErrNotFound
	}
	if u.Attributes == nil {
		u.Attributes = map[string]string{}
	}
	return u, err
}

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
func (r *PostgresRepository) ResolveIdentity(ctx context.Context, provider Provider, claims IdentityClaims) (IdentityResolution, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return IdentityResolution{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := resolveIdentity(ctx, tx, provider, claims)
	if err != nil {
		return IdentityResolution{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return IdentityResolution{}, err
	}
	return result, nil
}

func resolveIdentity(ctx context.Context, tx pgx.Tx, provider Provider, claims IdentityClaims) (IdentityResolution, error) {
	if strings.TrimSpace(claims.Subject) == "" {
		return IdentityResolution{}, ErrBrokerFailed
	}
	lockKey := provider.ID.String() + "\n" + claims.Subject
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return IdentityResolution{}, err
	}
	if u, err := findIdentityUser(ctx, tx, provider.ID, claims.Subject); err == nil {
		return IdentityResolution{User: u}, nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return IdentityResolution{}, err
	}
	if !claims.EmailVerified || strings.TrimSpace(claims.Email) == "" {
		return IdentityResolution{}, ErrVerifiedEmailRequired
	}
	return resolveAndLinkIdentity(ctx, tx, provider, claims)
}

func findIdentityUser(ctx context.Context, tx pgx.Tx, providerID uuid.UUID, subject string) (users.User, error) {
	query := `SELECT u.` + strings.ReplaceAll(brokerUserCols, ",", ",u.") + ` FROM users u
		JOIN federated_identities fi ON fi.user_id=u.id
		WHERE fi.provider_id=$1 AND fi.external_subject=$2 FOR UPDATE OF u`
	return scanResolvedUser(tx.QueryRow(ctx, query, providerID, subject))
}

func findUserByEmail(ctx context.Context, tx pgx.Tx, email string) (users.User, error) {
	query := `SELECT u.` + strings.ReplaceAll(brokerUserCols, ",", ",u.") + ` FROM users u
		WHERE lower(u.email)=lower($1) AND u.status <> 'deleted' ORDER BY u.created_at LIMIT 1 FOR UPDATE`
	return scanResolvedUser(tx.QueryRow(ctx, query, email))
}

func resolveAndLinkIdentity(ctx context.Context, tx pgx.Tx, provider Provider, claims IdentityClaims) (IdentityResolution, error) {
	u, err := findUserByEmail(ctx, tx, claims.Email)
	created := false
	if errors.Is(err, storage.ErrNotFound) {
		u, created, err = provisionIdentityUser(ctx, tx, provider, claims)
	}
	if err != nil {
		return IdentityResolution{}, err
	}
	if u.MFAEnabled {
		return IdentityResolution{}, ErrLinkRequiresMFA
	}
	var linkedUserID uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO federated_identities(provider_id,external_subject,user_id,email)
		VALUES($1,$2,$3,$4) ON CONFLICT (provider_id,external_subject) DO NOTHING RETURNING user_id`,
		provider.ID, claims.Subject, u.ID, claims.Email).Scan(&linkedUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		winner, findErr := findIdentityUser(ctx, tx, provider.ID, claims.Subject)
		return IdentityResolution{User: winner}, findErr
	}
	if err != nil {
		return IdentityResolution{}, err
	}
	return IdentityResolution{User: u, UserCreated: created, IdentityCreated: true}, nil
}

func provisionIdentityUser(ctx context.Context, tx pgx.Tx, provider Provider, claims IdentityClaims) (users.User, bool, error) {
	sum := sha256.Sum256([]byte(provider.ID.String() + "\n" + claims.Subject))
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		username = strings.SplitN(claims.Email, "@", 2)[0]
	}
	if username == "" {
		username = "federated-" + hex.EncodeToString(sum[:4])
	}
	u, err := insertFederatedUser(ctx, tx, username, claims.Email)
	if err == nil {
		return u, true, nil
	}
	if !errors.Is(err, storage.ErrConflict) {
		return users.User{}, false, err
	}
	if existing, findErr := findUserByEmail(ctx, tx, claims.Email); findErr == nil {
		return existing, false, nil
	}
	u, err = insertFederatedUser(ctx, tx, username+"-"+hex.EncodeToString(sum[:4]), claims.Email)
	if err == nil {
		return u, true, nil
	}
	if existing, findErr := findUserByEmail(ctx, tx, claims.Email); findErr == nil {
		return existing, false, nil
	}
	return users.User{}, false, err
}

func insertFederatedUser(ctx context.Context, tx pgx.Tx, username, email string) (users.User, error) {
	query := `INSERT INTO users(username,email,status,source,email_verified)
		VALUES($1,$2,'active','federated',true) ON CONFLICT DO NOTHING RETURNING ` + brokerUserCols
	u, err := scanResolvedUser(tx.QueryRow(ctx, query, username, email))
	if errors.Is(err, storage.ErrNotFound) {
		return users.User{}, storage.ErrConflict
	}
	return u, err
}
