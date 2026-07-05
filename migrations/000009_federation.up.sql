CREATE TABLE IF NOT EXISTS identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL UNIQUE, -- slug used in /oauth2/broker/{code}/...
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'oidc', -- 'google' | 'github' | 'oidc'
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL DEFAULT '', -- AES-256-GCM encrypted
    authorize_url TEXT NOT NULL DEFAULT '',
    token_url TEXT NOT NULL DEFAULT '',
    userinfo_url TEXT NOT NULL DEFAULT '',
    scopes TEXT NOT NULL DEFAULT 'openid profile email',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS federated_identities (
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, external_subject)
);
CREATE INDEX IF NOT EXISTS idx_federated_identities_user ON federated_identities(user_id);

INSERT INTO permissions(code, resource, action, description)
VALUES
    ('identity_providers:read', 'identity_providers', 'read', 'Read identity providers'),
    ('identity_providers:create', 'identity_providers', 'create', 'Create identity providers'),
    ('identity_providers:update', 'identity_providers', 'update', 'Update identity providers'),
    ('identity_providers:delete', 'identity_providers', 'delete', 'Delete identity providers')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code IN ('identity_providers:read', 'identity_providers:create', 'identity_providers:update', 'identity_providers:delete')
WHERE r.code = 'admin'
ON CONFLICT DO NOTHING;
