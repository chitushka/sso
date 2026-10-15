CREATE OR REPLACE FUNCTION write_security_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    row_data JSONB;
    target TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD IS NOT DISTINCT FROM NEW THEN
        RETURN NEW;
    END IF;

    row_data := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    target := COALESCE(
        NULLIF(row_data->>'id', ''),
        NULLIF(concat_ws(':',
            NULLIF(row_data->>'user_id', ''),
            NULLIF(row_data->>'role_id', ''),
            NULLIF(row_data->>'permission_id', ''),
            NULLIF(row_data->>'group_id', ''),
            NULLIF(row_data->>'provider_id', ''),
            NULLIF(row_data->>'client_id', '')
        ), ''),
        'row'
    );

    INSERT INTO audit_logs(action, target_type, target_id)
    VALUES ('security.' || TG_TABLE_NAME || '.' || lower(TG_OP), TG_TABLE_NAME, target);

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DO $$
DECLARE
    table_name TEXT;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'users', 'roles', 'permissions', 'role_permissions', 'user_roles',
        'groups', 'group_roles', 'user_groups', 'ldap_providers',
        'ldap_group_mappings', 'oauth_clients', 'user_consents',
        'mfa_recovery_codes', 'identity_providers', 'federated_identities',
        'oidc_signing_keys', 'encryption_key_metadata'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER security_audit AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION write_security_audit()',
            table_name
        );
    END LOOP;

    FOREACH table_name IN ARRAY ARRAY[
        'sessions', 'refresh_tokens', 'one_time_tokens', 'login_attempts'
    ] LOOP
        EXECUTE format(
            'CREATE TRIGGER security_audit AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION write_security_audit()',
            table_name
        );
    END LOOP;
END;
$$;
