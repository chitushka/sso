CREATE TABLE IF NOT EXISTS oidc_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kid TEXT NOT NULL UNIQUE,
    alg TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','retiring','retired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_oidc_signing_keys_status ON oidc_signing_keys(status);
