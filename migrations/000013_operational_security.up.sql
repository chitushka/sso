CREATE TABLE encryption_key_metadata (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    verifier TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO permissions(code, resource, action, description)
VALUES ('metrics:read', 'metrics', 'read', 'Read Prometheus metrics')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.code = 'metrics:read'
WHERE r.code = 'admin'
ON CONFLICT DO NOTHING;
