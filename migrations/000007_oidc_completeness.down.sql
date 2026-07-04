DROP TABLE IF EXISTS user_consents;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS post_logout_redirect_uris,
    DROP COLUMN IF EXISTS backchannel_logout_uri,
    DROP COLUMN IF EXISTS skip_consent;
