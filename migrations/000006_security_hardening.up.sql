CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (username, ip)
);

INSERT INTO permissions(code, resource, action, description)
VALUES
    ('roles:delete', 'roles', 'delete', 'Delete roles'),
    ('ldap:delete', 'ldap', 'delete', 'Delete LDAP providers'),
    ('oauth_clients:delete', 'oauth_clients', 'delete', 'Delete OAuth clients'),
    ('audit:read', 'audit', 'read', 'Read audit logs')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('roles:delete', 'ldap:delete', 'oauth_clients:delete', 'audit:read')
WHERE r.code = 'admin'
ON CONFLICT DO NOTHING;
