DELETE FROM permissions WHERE code IN ('roles:delete', 'ldap:delete', 'oauth_clients:delete', 'audit:read');

DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS refresh_tokens;
