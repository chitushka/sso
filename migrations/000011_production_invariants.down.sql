ALTER TABLE identity_providers DROP CONSTRAINT IF EXISTS identity_providers_type_check;
ALTER TABLE oidc_signing_keys
    DROP CONSTRAINT IF EXISTS oidc_signing_keys_alg_check;
ALTER TABLE one_time_tokens DROP CONSTRAINT IF EXISTS one_time_tokens_purpose_check;
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_mfa_counter_check,
    DROP CONSTRAINT IF EXISTS users_source_check,
    DROP CONSTRAINT IF EXISTS users_status_check;
DROP INDEX IF EXISTS uq_users_email_normalized;
DROP INDEX IF EXISTS uq_oidc_signing_keys_active;
