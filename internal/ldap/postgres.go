package ldap

import (
	"context"
	"errors"
	"github.com/chitushka/sso/internal/secrets"
	"github.com/chitushka/sso/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool      *pgxpool.Pool
	encryptor secrets.Encryptor
}

func NewPostgresRepository(pool *pgxpool.Pool, encryptor secrets.Encryptor) *PostgresRepository {
	return &PostgresRepository{pool: pool, encryptor: encryptor}
}

const ldapCols = "id,name,host,port,use_tls,start_tls,bind_dn,bind_password,base_dn,user_filter,username_attribute,email_attribute,display_name_attribute,group_attribute,enabled,created_at,updated_at"

func (r *PostgresRepository) scanProvider(row pgx.Row) (Provider, error) {
	var p Provider
	err := row.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.UseTLS, &p.StartTLS, &p.BindDN, &p.BindPassword, &p.BaseDN, &p.UserFilter, &p.UsernameAttribute, &p.EmailAttribute, &p.DisplayNameAttribute, &p.GroupAttribute, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, storage.ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.BindPassword, err = r.encryptor.Decrypt(p.BindPassword)
	return p, err
}
func (r *PostgresRepository) Create(ctx context.Context, p Provider) (Provider, error) {
	enc, err := r.encryptor.Encrypt(p.BindPassword)
	if err != nil {
		return Provider{}, err
	}
	return r.scanProvider(r.pool.QueryRow(ctx, `INSERT INTO ldap_providers(name,host,port,use_tls,start_tls,bind_dn,bind_password,base_dn,user_filter,username_attribute,email_attribute,display_name_attribute,group_attribute,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING `+ldapCols, p.Name, p.Host, p.Port, p.UseTLS, p.StartTLS, p.BindDN, enc, p.BaseDN, p.UserFilter, p.UsernameAttribute, p.EmailAttribute, p.DisplayNameAttribute, p.GroupAttribute, p.Enabled))
}
func (r *PostgresRepository) List(ctx context.Context) ([]Provider, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+ldapCols+` FROM ldap_providers ORDER BY created_at DESC`)
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
func (r *PostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (Provider, error) {
	return r.scanProvider(r.pool.QueryRow(ctx, `SELECT `+ldapCols+` FROM ldap_providers WHERE id=$1`, id))
}
func (r *PostgresRepository) FirstEnabled(ctx context.Context) (Provider, error) {
	return r.scanProvider(r.pool.QueryRow(ctx, `SELECT `+ldapCols+` FROM ldap_providers WHERE enabled=true ORDER BY created_at ASC LIMIT 1`))
}
func (r *PostgresRepository) Update(ctx context.Context, p Provider) (Provider, error) {
	enc, err := r.encryptor.Encrypt(p.BindPassword)
	if err != nil {
		return Provider{}, err
	}
	return r.scanProvider(r.pool.QueryRow(ctx, `UPDATE ldap_providers SET name=$2,host=$3,port=$4,use_tls=$5,start_tls=$6,bind_dn=$7,bind_password=$8,base_dn=$9,user_filter=$10,username_attribute=$11,email_attribute=$12,display_name_attribute=$13,group_attribute=$14,enabled=$15,updated_at=now() WHERE id=$1 RETURNING `+ldapCols, p.ID, p.Name, p.Host, p.Port, p.UseTLS, p.StartTLS, p.BindDN, enc, p.BaseDN, p.UserFilter, p.UsernameAttribute, p.EmailAttribute, p.DisplayNameAttribute, p.GroupAttribute, p.Enabled))
}

func (r *PostgresRepository) ListGroupMappings(ctx context.Context, providerID uuid.UUID) ([]GroupMapping, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,provider_id,ldap_group,group_id,created_at FROM ldap_group_mappings WHERE provider_id=$1 ORDER BY ldap_group`, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GroupMapping{}
	for rows.Next() {
		var m GroupMapping
		if err := rows.Scan(&m.ID, &m.ProviderID, &m.LDAPGroup, &m.GroupID, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) CreateGroupMapping(ctx context.Context, m GroupMapping) (GroupMapping, error) {
	err := r.pool.QueryRow(ctx, `INSERT INTO ldap_group_mappings(provider_id,ldap_group,group_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id,created_at`, m.ProviderID, m.LDAPGroup, m.GroupID).Scan(&m.ID, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, storage.ErrConflict
	}
	return m, err
}
func (r *PostgresRepository) DeleteGroupMapping(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM ldap_group_mappings WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return err
}
func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM ldap_providers WHERE id=$1`, id)
	return err
}
