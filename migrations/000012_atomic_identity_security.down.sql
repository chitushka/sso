ALTER TABLE users DROP CONSTRAINT fk_users_ldap_provider;
ALTER TABLE users ADD CONSTRAINT fk_users_ldap_provider
    FOREIGN KEY (ldap_provider_id) REFERENCES ldap_providers(id) ON DELETE SET NULL;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_ldap_identity_consistent;
DROP INDEX IF EXISTS users_ldap_identity_unique;
