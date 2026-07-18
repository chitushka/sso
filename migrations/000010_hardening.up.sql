-- Release 1.1 hardening.
--
-- tokens_invalid_before: any access token whose iat is not strictly after this
-- moment is rejected by BearerAuth. Set on "sign out everywhere", password
-- reset and account block/delete to make JWT access tokens revocable.
--
-- mfa_last_used_counter: the last accepted TOTP time-step, so a code cannot be
-- replayed within its validity window.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tokens_invalid_before TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mfa_last_used_counter BIGINT NOT NULL DEFAULT 0;
