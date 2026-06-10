ALTER TABLE users
    DROP COLUMN IF EXISTS ldap_dn,
    DROP COLUMN IF EXISTS ldap_provider_id;

UPDATE users SET password_hash = '' WHERE password_hash IS NULL;
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

DROP TABLE IF EXISTS ldap_providers;
