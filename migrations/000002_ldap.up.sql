CREATE TABLE IF NOT EXISTS ldap_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 389 CHECK (port > 0 AND port <= 65535),
    use_tls BOOLEAN NOT NULL DEFAULT false,
    start_tls BOOLEAN NOT NULL DEFAULT false,
    bind_dn TEXT NOT NULL,
    bind_password TEXT NOT NULL,
    base_dn TEXT NOT NULL,
    user_filter TEXT NOT NULL DEFAULT '(&(objectClass=user)(sAMAccountName={username}))',
    username_attribute TEXT NOT NULL DEFAULT 'sAMAccountName',
    email_attribute TEXT NOT NULL DEFAULT 'mail',
    display_name_attribute TEXT NOT NULL DEFAULT 'displayName',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (NOT (use_tls AND start_tls))
);
ALTER TABLE users ADD CONSTRAINT fk_users_ldap_provider FOREIGN KEY (ldap_provider_id) REFERENCES ldap_providers(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_ldap_providers_enabled ON ldap_providers(enabled);
CREATE INDEX IF NOT EXISTS idx_users_ldap_provider_id ON users(ldap_provider_id);
