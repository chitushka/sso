-- Remove legacy plaintext signing keys. The application will generate a new encrypted key.
DELETE FROM oidc_signing_keys
WHERE private_key_pem NOT LIKE 'enc:v1:%';

CREATE UNIQUE INDEX IF NOT EXISTS uq_oidc_signing_keys_active
    ON oidc_signing_keys ((status))
    WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_normalized
    ON users (lower(email))
    WHERE email <> '' AND status <> 'deleted';

ALTER TABLE users
    ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'blocked', 'pending', 'deleted')),
    ADD CONSTRAINT users_source_check CHECK (source IN ('local', 'ldap', 'federated')),
    ADD CONSTRAINT users_mfa_counter_check CHECK (mfa_last_used_counter >= 0);

ALTER TABLE one_time_tokens
    ADD CONSTRAINT one_time_tokens_purpose_check CHECK (purpose IN ('password_reset', 'email_verify'));

ALTER TABLE oidc_signing_keys
    ADD CONSTRAINT oidc_signing_keys_alg_check CHECK (alg = 'RS256');

ALTER TABLE identity_providers
    ADD CONSTRAINT identity_providers_type_check CHECK (type IN ('google', 'github', 'oidc'));

