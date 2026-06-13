CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    resource TEXT NOT NULL,
    action TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(resource, action)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

INSERT INTO roles(code, name, description)
VALUES
    ('admin', 'Administrator', 'Full system administrator'),
    ('user', 'User', 'Regular authenticated user')
ON CONFLICT (code) DO NOTHING;

INSERT INTO permissions(code, resource, action, description)
VALUES
    ('users:read', 'users', 'read', 'Read users'),
    ('users:create', 'users', 'create', 'Create users'),
    ('users:update', 'users', 'update', 'Update users'),
    ('users:delete', 'users', 'delete', 'Delete users'),
    ('roles:read', 'roles', 'read', 'Read roles'),
    ('roles:create', 'roles', 'create', 'Create roles'),
    ('roles:update', 'roles', 'update', 'Update roles'),
    ('roles:assign', 'roles', 'assign', 'Assign roles'),
    ('permissions:read', 'permissions', 'read', 'Read permissions'),
    ('permissions:assign', 'permissions', 'assign', 'Assign permissions'),
    ('ldap:read', 'ldap', 'read', 'Read LDAP providers'),
    ('ldap:create', 'ldap', 'create', 'Create LDAP providers'),
    ('ldap:update', 'ldap', 'update', 'Update LDAP providers'),
    ('ldap:test', 'ldap', 'test', 'Test LDAP providers'),
    ('oauth_clients:read', 'oauth_clients', 'read', 'Read OAuth clients'),
    ('oauth_clients:create', 'oauth_clients', 'create', 'Create OAuth clients'),
    ('oauth_clients:update', 'oauth_clients', 'update', 'Update OAuth clients')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.code = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('users:read')
WHERE r.code = 'user'
ON CONFLICT DO NOTHING;

-- Legacy bootstrap compatibility: if the database already has users from v0.1-v0.4
-- and no role assignments yet, grant admin to the earliest created user.
INSERT INTO user_roles(user_id, role_id)
SELECT u.id, r.id
FROM users u
JOIN roles r ON r.code = 'admin'
WHERE NOT EXISTS (SELECT 1 FROM user_roles)
ORDER BY u.created_at ASC
LIMIT 1
ON CONFLICT DO NOTHING;
