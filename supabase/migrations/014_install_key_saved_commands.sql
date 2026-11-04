-- Persist the generated install command beside its private install-key secret so the
-- dashboard can show the same command again after sign-out. The command embeds a
-- single-use claim token, so it is encrypted at rest and only returned to its owner.

ALTER TABLE private.install_key_secrets
    ADD COLUMN IF NOT EXISTS encrypted_command BYTEA,
    ADD COLUMN IF NOT EXISTS command_key_version TEXT;

CREATE OR REPLACE FUNCTION public.store_install_key_command(
    p_key_id TEXT,
    p_owner_key TEXT,
    p_program TEXT,
    p_encrypted_command_base64 TEXT,
    p_key_version TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, private
AS $$
DECLARE
    affected_rows INTEGER;
BEGIN
    IF p_encrypted_command_base64 IS NULL OR p_key_version IS NULL THEN
        RETURN FALSE;
    END IF;

    UPDATE private.install_key_secrets AS secret
    SET encrypted_command = decode(p_encrypted_command_base64, 'base64'),
        command_key_version = p_key_version
    FROM public.install_key_records AS key_record
    WHERE secret.key_id = p_key_id
      AND secret.owner_key = p_owner_key
      AND key_record.key_id = secret.key_id
      AND key_record.owner_key = p_owner_key
      AND key_record.program = p_program
      AND key_record.active IS TRUE
      AND key_record.payment_status = 'paid'
      AND key_record.entitlements_status = 'active'
      AND key_record.issued_after_payment IS TRUE;

    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    RETURN affected_rows = 1;
END;
$$;

CREATE OR REPLACE FUNCTION public.get_install_key_commands(
    p_owner_key TEXT
)
RETURNS TABLE (
    key_id TEXT,
    program TEXT,
    key_version TEXT,
    encrypted_command_base64 TEXT,
    claimed BOOLEAN
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, private
AS $$
    SELECT
        secret.key_id,
        key_record.program,
        secret.command_key_version,
        encode(secret.encrypted_command, 'base64'),
        secret.claimed_at IS NOT NULL
    FROM private.install_key_secrets AS secret
    JOIN public.install_key_records AS key_record
      ON key_record.key_id = secret.key_id
     AND key_record.owner_key = secret.owner_key
    WHERE secret.owner_key = p_owner_key
      AND secret.encrypted_command IS NOT NULL
      AND key_record.active IS TRUE
      AND key_record.payment_status = 'paid'
      AND key_record.entitlements_status = 'active'
      AND key_record.issued_after_payment IS TRUE;
$$;

REVOKE ALL ON FUNCTION public.store_install_key_command(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.get_install_key_commands(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.store_install_key_command(TEXT, TEXT, TEXT, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.get_install_key_commands(TEXT) TO service_role;
