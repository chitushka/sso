ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_ldap_provider;
DROP TABLE IF EXISTS ldap_providers;
