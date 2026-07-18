ALTER TABLE users
    DROP COLUMN IF EXISTS tokens_invalid_before,
    DROP COLUMN IF EXISTS mfa_last_used_counter;
