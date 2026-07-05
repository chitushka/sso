DELETE FROM permissions WHERE code IN ('identity_providers:read', 'identity_providers:create', 'identity_providers:update', 'identity_providers:delete');

DROP TABLE IF EXISTS federated_identities;
DROP TABLE IF EXISTS identity_providers;
