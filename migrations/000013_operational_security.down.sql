DELETE FROM role_permissions
WHERE permission_id IN (SELECT id FROM permissions WHERE code = 'metrics:read');
DELETE FROM permissions WHERE code = 'metrics:read';
DROP TABLE IF EXISTS encryption_key_metadata;
