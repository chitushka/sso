-- An LDAP identity is owned by one provider and one immutable directory DN.
-- Username is only a mutable display/login attribute and must never be used to
-- attach a directory login to an existing local or federated account.
CREATE UNIQUE INDEX users_ldap_identity_unique
    ON users (ldap_provider_id, lower(ldap_dn))
    WHERE source = 'ldap';

ALTER TABLE users
    ADD CONSTRAINT users_ldap_identity_consistent CHECK (
        (source = 'ldap' AND ldap_provider_id IS NOT NULL AND ldap_dn IS NOT NULL AND btrim(ldap_dn) <> '')
        OR
        (source <> 'ldap' AND ldap_provider_id IS NULL AND ldap_dn IS NULL)
    );

-- SET NULL would violate the identity invariant and orphan LDAP accounts.
ALTER TABLE users DROP CONSTRAINT fk_users_ldap_provider;
ALTER TABLE users ADD CONSTRAINT fk_users_ldap_provider
    FOREIGN KEY (ldap_provider_id) REFERENCES ldap_providers(id) ON DELETE RESTRICT;
