DELETE FROM permissions WHERE code IN ('groups:read', 'groups:create', 'groups:update', 'groups:delete', 'groups:assign');

ALTER TABLE ldap_providers DROP COLUMN IF EXISTS group_attribute;

DROP TABLE IF EXISTS ldap_group_mappings;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS group_roles;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS one_time_tokens;

ALTER TABLE users
    DROP COLUMN IF EXISTS first_name,
    DROP COLUMN IF EXISTS last_name,
    DROP COLUMN IF EXISTS attributes,
    DROP COLUMN IF EXISTS email_verified,
    DROP COLUMN IF EXISTS mfa_enabled,
    DROP COLUMN IF EXISTS mfa_secret;
