DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'users', 'roles', 'permissions', 'role_permissions', 'user_roles',
        'groups', 'group_roles', 'user_groups', 'ldap_providers',
        'ldap_group_mappings', 'oauth_clients', 'user_consents',
        'mfa_recovery_codes', 'identity_providers', 'federated_identities',
        'oidc_signing_keys', 'encryption_key_metadata', 'sessions',
        'refresh_tokens', 'one_time_tokens', 'login_attempts'
    ] LOOP
        IF to_regclass('public.' || table_name) IS NOT NULL THEN
            EXECUTE format('DROP TRIGGER IF EXISTS security_audit ON %I', table_name);
        END IF;
    END LOOP;
END;
$$;

DROP FUNCTION IF EXISTS write_security_audit();
