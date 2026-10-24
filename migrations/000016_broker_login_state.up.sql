CREATE TABLE broker_login_states (
    state_hash BYTEA PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    provider_code TEXT NOT NULL REFERENCES identity_providers(code) ON UPDATE CASCADE ON DELETE CASCADE,
    continue_url TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX broker_login_states_expires_at_idx ON broker_login_states(expires_at);
