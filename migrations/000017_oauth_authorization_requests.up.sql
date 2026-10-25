CREATE TABLE oauth_authorization_requests (
    request_hash TEXT PRIMARY KEY CHECK (length(request_hash) = 64),
    response_type TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX oauth_authorization_requests_expires_at_idx ON oauth_authorization_requests(expires_at);
