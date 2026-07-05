ALTER TABLE users
    ADD COLUMN IF NOT EXISTS first_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS mfa_secret TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS one_time_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL, -- 'password_reset' | 'email_verify'
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_one_time_tokens_user ON one_time_tokens(user_id, purpose);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user ON mfa_recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_roles (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, role_id)
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    -- 'manual' memberships are managed by admins, 'ldap' ones are synced on login
    source TEXT NOT NULL DEFAULT 'manual',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);

CREATE TABLE IF NOT EXISTS ldap_group_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES ldap_providers(id) ON DELETE CASCADE,
    ldap_group TEXT NOT NULL, -- DN or name as returned by the group attribute
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider_id, ldap_group, group_id)
);

ALTER TABLE ldap_providers
    ADD COLUMN IF NOT EXISTS group_attribute TEXT NOT NULL DEFAULT 'memberOf';

INSERT INTO permissions(code, resource, action, description)
VALUES
    ('groups:read', 'groups', 'read', 'Read groups'),
    ('groups:create', 'groups', 'create', 'Create groups'),
    ('groups:update', 'groups', 'update', 'Update groups'),
    ('groups:delete', 'groups', 'delete', 'Delete groups'),
    ('groups:assign', 'groups', 'assign', 'Assign groups and group roles')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('groups:read', 'groups:create', 'groups:update', 'groups:delete', 'groups:assign')
WHERE r.code = 'admin'
ON CONFLICT DO NOTHING;
