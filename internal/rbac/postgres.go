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

// HasPermission checks roles granted directly and via group membership.
func (r *PostgresRepository) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1
		FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id
		WHERE p.resource = $2 AND p.action = $3
		  AND rp.role_id IN (
			SELECT role_id FROM user_roles WHERE user_id = $1
			UNION
			SELECT gr.role_id FROM user_groups ug JOIN group_roles gr ON gr.group_id = ug.group_id WHERE ug.user_id = $1
		  )
	)`, userID, resource, action).Scan(&ok)
	return ok, err
}

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.Code, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, storage.ErrNotFound
	}
	return g, err
}

const groupCols = "id,code,name,coalesce(description,''),created_at,updated_at"

func (r *PostgresRepository) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+groupCols+` FROM groups ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) CreateGroup(ctx context.Context, g Group) (Group, error) {
	created, err := scanGroup(r.pool.QueryRow(ctx, `INSERT INTO groups(code,name,description) VALUES($1,$2,$3) RETURNING `+groupCols, g.Code, g.Name, g.Description))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return created, storage.ErrConflict
		}
	}
	return created, err
}
func (r *PostgresRepository) FindGroupByID(ctx context.Context, id uuid.UUID) (Group, error) {
	return scanGroup(r.pool.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id=$1`, id))
}
func (r *PostgresRepository) UpdateGroup(ctx context.Context, g Group) (Group, error) {
	return scanGroup(r.pool.QueryRow(ctx, `UPDATE groups SET name=$2,description=$3,updated_at=now() WHERE id=$1 RETURNING `+groupCols, g.ID, g.Name, g.Description))
}
func (r *PostgresRepository) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return err
}
func (r *PostgresRepository) ListGroupRoles(ctx context.Context, groupID uuid.UUID) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `SELECT ro.id,ro.code,ro.name,coalesce(ro.description,''),ro.created_at,ro.updated_at FROM roles ro JOIN group_roles gr ON gr.role_id=ro.id WHERE gr.group_id=$1 ORDER BY ro.code`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Role{}
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) AssignRoleToGroup(ctx context.Context, groupID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO group_roles(group_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, groupID, roleID)
	return err
}
func (r *PostgresRepository) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM group_roles WHERE group_id=$1 AND role_id=$2`, groupID, roleID)
	return err
}
func (r *PostgresRepository) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]Group, error) {
	rows, err := r.pool.Query(ctx, `SELECT g.id,g.code,g.name,coalesce(g.description,''),g.created_at,g.updated_at FROM groups g JOIN user_groups ug ON ug.group_id=g.id WHERE ug.user_id=$1 ORDER BY g.code`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (r *PostgresRepository) AssignGroupToUser(ctx context.Context, userID, groupID uuid.UUID, source string) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO user_groups(user_id,group_id,source) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, userID, groupID, source)
	return err
}
func (r *PostgresRepository) RemoveGroupFromUser(ctx context.Context, userID, groupID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM user_groups WHERE user_id=$1 AND group_id=$2`, userID, groupID)
	return err
}

// SyncLDAPGroups replaces the user's ldap-sourced memberships with the groups
// mapped from the directory groups seen at login; manual memberships stay.
func (r *PostgresRepository) SyncLDAPGroups(ctx context.Context, userID, providerID uuid.UUID, ldapGroups []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM user_groups WHERE user_id=$1 AND source='ldap'`, userID); err != nil {
		return err
	}
	if len(ldapGroups) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO user_groups(user_id,group_id,source)
			SELECT $1, m.group_id, 'ldap' FROM ldap_group_mappings m
			WHERE m.provider_id=$2 AND m.ldap_group = ANY($3)
			ON CONFLICT DO NOTHING`, userID, providerID, ldapGroups); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
