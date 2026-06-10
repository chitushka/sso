package ldap

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

func scanProvider(row pgx.Row) (Provider, error) {
	var p Provider
	err := row.Scan(
		&p.ID, &p.Name, &p.Host, &p.Port, &p.UseTLS, &p.StartTLS,
		&p.BindDN, &p.BindPassword, &p.BaseDN, &p.UserFilter,
		&p.UsernameAttribute, &p.EmailAttribute, &p.DisplayNameAttribute,
		&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, storage.ErrNotFound
	}
	return p, err
}

const providerColumns = `id,name,host,port,use_tls,start_tls,bind_dn,bind_password,base_dn,user_filter,username_attribute,email_attribute,display_name_attribute,enabled,created_at,updated_at`

func (r *PostgresRepository) Create(ctx context.Context, p Provider) (Provider, error) {
	row := r.pool.QueryRow(ctx, `INSERT INTO ldap_providers(name,host,port,use_tls,start_tls,bind_dn,bind_password,base_dn,user_filter,username_attribute,email_attribute,display_name_attribute,enabled)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING `+providerColumns,
		p.Name, p.Host, p.Port, p.UseTLS, p.StartTLS, p.BindDN, p.BindPassword, p.BaseDN, p.UserFilter, p.UsernameAttribute, p.EmailAttribute, p.DisplayNameAttribute, p.Enabled)
	created, err := scanProvider(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return created, storage.ErrConflict
		}
	}
	return created, err
}

func (r *PostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (Provider, error) {
	return scanProvider(r.pool.QueryRow(ctx, `SELECT `+providerColumns+` FROM ldap_providers WHERE id=$1`, id))
}

func (r *PostgresRepository) List(ctx context.Context, limit, offset int) ([]Provider, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+providerColumns+` FROM ldap_providers ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func (r *PostgresRepository) ListEnabled(ctx context.Context) ([]Provider, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+providerColumns+` FROM ldap_providers WHERE enabled=true ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProviders(rows)
}

func scanProviders(rows pgx.Rows) ([]Provider, error) {
	var out []Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) Update(ctx context.Context, p Provider) (Provider, error) {
	return scanProvider(r.pool.QueryRow(ctx, `UPDATE ldap_providers
		SET name=$2,host=$3,port=$4,use_tls=$5,start_tls=$6,bind_dn=$7,bind_password=$8,base_dn=$9,user_filter=$10,
		username_attribute=$11,email_attribute=$12,display_name_attribute=$13,enabled=$14,updated_at=now()
		WHERE id=$1 RETURNING `+providerColumns,
		p.ID, p.Name, p.Host, p.Port, p.UseTLS, p.StartTLS, p.BindDN, p.BindPassword, p.BaseDN, p.UserFilter,
		p.UsernameAttribute, p.EmailAttribute, p.DisplayNameAttribute, p.Enabled))
}

func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM ldap_providers WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}
