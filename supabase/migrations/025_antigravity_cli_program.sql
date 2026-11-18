BEGIN;

CREATE OR REPLACE FUNCTION public.issue_install_key_record_with_secret(
    p_install_key_record JSONB,
    p_encrypted_key_base64 TEXT,
    p_key_version TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, private
AS $$
DECLARE
    key_id TEXT;
    owner_key TEXT;
    program TEXT;
    raw_key_hash TEXT;
    encrypted_key BYTEA;
BEGIN
    IF jsonb_typeof(p_install_key_record) IS DISTINCT FROM 'object'
       OR p_key_version IS DISTINCT FROM 'v1'
       OR p_encrypted_key_base64 IS NULL
       OR btrim(p_encrypted_key_base64) = '' THEN
        RETURN FALSE;
    END IF;

    key_id := NULLIF(btrim(p_install_key_record->>'key_id'), '');
    owner_key := NULLIF(btrim(p_install_key_record->>'owner_key'), '');
    program := p_install_key_record->>'program';
    raw_key_hash := p_install_key_record->>'raw_key_hash';

    IF key_id IS NULL
       OR owner_key IS NULL
       OR program IS NULL
       OR program NOT IN ('openclaw', 'claude_code', 'cursor', 'goose', 'antigravity_cli', 'copilot', 'hermes')
       OR raw_key_hash IS NULL
       OR raw_key_hash !~ '^[0-9a-f]{64}$'
       OR NULLIF(btrim(p_install_key_record->>'masked_key'), '') IS NULL
       OR p_install_key_record->>'active' IS DISTINCT FROM 'true'
       OR p_install_key_record->>'payment_status' IS DISTINCT FROM 'paid'
       OR p_install_key_record->>'entitlements_status' IS DISTINCT FROM 'active'
       OR p_install_key_record->>'issued_after_payment' IS DISTINCT FROM 'true' THEN
        RETURN FALSE;
    END IF;

    encrypted_key := decode(p_encrypted_key_base64, 'base64');
    IF octet_length(encrypted_key) = 0 THEN
        RETURN FALSE;
    END IF;

    INSERT INTO public.install_key_records (
        key_id,
        purchase_reference,
        subscription_id,
        owner_key,
        org_id,
        customer_id,
        program,
        checkout_session_id,
        raw_key_hash,
        masked_key,
        label,
        active,
        payment_status,
        entitlements_status,
        issued_after_payment,
        created_at,
        last_used_at,
        revoked_at,
        metadata
    )
    VALUES (
        key_id,
        NULLIF(p_install_key_record->>'purchase_reference', ''),
        COALESCE(p_install_key_record->>'subscription_id', ''),
        owner_key,
        NULLIF(p_install_key_record->>'org_id', ''),
        NULLIF(p_install_key_record->>'customer_id', ''),
        program,
        NULLIF(p_install_key_record->>'checkout_session_id', ''),
        raw_key_hash,
        p_install_key_record->>'masked_key',
        COALESCE(p_install_key_record->>'label', ''),
        TRUE,
        'paid',
        'active',
        TRUE,
        COALESCE((p_install_key_record->>'created_at')::TIMESTAMPTZ, NOW()),
        NULLIF(p_install_key_record->>'last_used_at', '')::TIMESTAMPTZ,
        NULLIF(p_install_key_record->>'revoked_at', '')::TIMESTAMPTZ,
        COALESCE(p_install_key_record->'metadata', '{}'::JSONB)
    );

    INSERT INTO private.install_key_secrets (
        key_id,
        encrypted_key,
        key_version,
        owner_key,
        metadata
    )
    VALUES (
        key_id,
        encrypted_key,
        p_key_version,
        owner_key,
        '{"encryption":"fernet-hkdf-sha256"}'::JSONB
    );

    RETURN TRUE;
EXCEPTION
    WHEN unique_violation THEN
        RETURN FALSE;
END;
$$;

REVOKE ALL ON FUNCTION public.issue_install_key_record_with_secret(JSONB, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_install_key_record_with_secret(JSONB, TEXT, TEXT) TO service_role;
COMMIT;
