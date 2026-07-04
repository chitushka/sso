ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS skip_consent BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS user_consents (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);
