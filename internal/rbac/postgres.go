package rbac

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

func scanRole(row pgx.Row) (Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.Code, &r.Name, &r.Description, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, storage.ErrNotFound
	}
	return r, err
}

func scanPermission(row pgx.Row) (Permission, error) {
	var p Permission
	err := row.Scan(&p.ID, &p.Code, &p.Resource, &p.Action, &p.Description, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, storage.ErrNotFound
	}
	return p, err
}

func (r *PostgresRepository) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,code,name,coalesce(description,''),created_at,updated_at FROM roles ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) CreateRole(ctx context.Context, role Role) (Role, error) {
	created, err := scanRole(r.pool.QueryRow(ctx, `INSERT INTO roles(code,name,description) VALUES($1,$2,$3) RETURNING id,code,name,coalesce(description,''),created_at,updated_at`, role.Code, role.Name, role.Description))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return created, storage.ErrConflict
		}
	}
	return created, err
}

func (r *PostgresRepository) FindRoleByCode(ctx context.Context, code string) (Role, error) {
	return scanRole(r.pool.QueryRow(ctx, `SELECT id,code,name,coalesce(description,''),created_at,updated_at FROM roles WHERE code=$1`, code))
}

func (r *PostgresRepository) FindRoleByID(ctx context.Context, id uuid.UUID) (Role, error) {
	return scanRole(r.pool.QueryRow(ctx, `SELECT id,code,name,coalesce(description,''),created_at,updated_at FROM roles WHERE id=$1`, id))
}

func (r *PostgresRepository) UpdateRole(ctx context.Context, role Role) (Role, error) {
	return scanRole(r.pool.QueryRow(ctx, `UPDATE roles SET name=$2,description=$3,updated_at=now() WHERE id=$1 RETURNING id,code,name,coalesce(description,''),created_at,updated_at`, role.ID, role.Name, role.Description))
}

func (r *PostgresRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM roles WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return err
}

func (r *PostgresRepository) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT id,code,resource,action,coalesce(description,''),created_at FROM permissions ORDER BY resource, action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		permission, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, permission)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) ListUserRoles(ctx context.Context, userID uuid.UUID) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `SELECT ro.id,ro.code,ro.name,coalesce(ro.description,''),ro.created_at,ro.updated_at FROM roles ro JOIN user_roles ur ON ur.role_id=ro.id WHERE ur.user_id=$1 ORDER BY ro.code`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) ListRolePermissions(ctx context.Context, roleID uuid.UUID) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT p.id,p.code,p.resource,p.action,coalesce(p.description,''),p.created_at FROM permissions p JOIN role_permissions rp ON rp.permission_id=p.id WHERE rp.role_id=$1 ORDER BY p.resource, p.action`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		permission, err := scanPermission(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, permission)
	}
	return out, rows.Err()
}

func (r *PostgresRepository) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, userID, roleID)
	return err
}

func (r *PostgresRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, userID, roleID)
	return err
}

func (r *PostgresRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, roleID, permissionID)
	return err
}

func (r *PostgresRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND permission_id=$2`, roleID, permissionID)
	return err
}

func (r *PostgresRepository) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1 AND p.resource = $2 AND p.action = $3
	)`, userID, resource, action).Scan(&ok)
	return ok, err
}
