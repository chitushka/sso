CREATE TABLE rate_limit_buckets (
    key_hash BYTEA PRIMARY KEY CHECK (octet_length(key_hash) = 32),
    tokens DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX rate_limit_buckets_expires_at_idx ON rate_limit_buckets(expires_at);
