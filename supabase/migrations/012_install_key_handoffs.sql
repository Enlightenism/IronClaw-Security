ALTER TABLE private.install_key_secrets
    ADD COLUMN IF NOT EXISTS claim_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS idx_private_install_key_secrets_claim_token_hash
    ON private.install_key_secrets (claim_token_hash)
    WHERE claim_token_hash IS NOT NULL;

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
       OR program NOT IN ('openclaw', 'claude_code', 'cursor', 'goose', 'gemini_cli', 'copilot', 'hermes')
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

CREATE OR REPLACE FUNCTION public.store_install_key_secret(
    p_key_id TEXT,
    p_owner_key TEXT,
    p_program TEXT,
    p_encrypted_key_base64 TEXT,
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
    IF p_key_id IS NULL OR btrim(p_key_id) = ''
       OR p_owner_key IS NULL OR btrim(p_owner_key) = ''
       OR p_program IS NULL OR btrim(p_program) = ''
       OR p_encrypted_key_base64 IS NULL OR btrim(p_encrypted_key_base64) = ''
       OR p_key_version IS DISTINCT FROM 'v1' THEN
        RETURN FALSE;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.install_key_records AS key_record
        WHERE key_record.key_id = p_key_id
          AND key_record.owner_key = p_owner_key
          AND key_record.program = p_program
          AND key_record.active IS TRUE
          AND key_record.payment_status = 'paid'
          AND key_record.entitlements_status = 'active'
          AND key_record.issued_after_payment IS TRUE
    ) THEN
        RETURN FALSE;
    END IF;

    INSERT INTO private.install_key_secrets (
        key_id,
        encrypted_key,
        key_version,
        owner_key,
        metadata
    )
    VALUES (
        p_key_id,
        decode(p_encrypted_key_base64, 'base64'),
        p_key_version,
        p_owner_key,
        '{"encryption":"fernet-hkdf-sha256"}'::jsonb
    )
    ON CONFLICT (key_id) DO UPDATE
    SET encrypted_key = EXCLUDED.encrypted_key,
        key_version = EXCLUDED.key_version,
        claim_token_hash = NULL,
        claim_expires_at = NULL,
        claimed_at = NULL,
        metadata = EXCLUDED.metadata
    WHERE private.install_key_secrets.owner_key = EXCLUDED.owner_key;

    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    RETURN affected_rows = 1;
END;
$$;

CREATE OR REPLACE FUNCTION public.issue_install_key_claim(
    p_key_id TEXT,
    p_owner_key TEXT,
    p_program TEXT,
    p_claim_token_hash TEXT,
    p_claim_expires_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, private
AS $$
DECLARE
    affected_rows INTEGER;
BEGIN
    IF p_claim_token_hash IS NULL OR p_claim_token_hash !~ '^[0-9a-f]{64}$'
       OR p_claim_expires_at IS NULL
       OR p_claim_expires_at <= NOW()
       OR p_claim_expires_at > NOW() + INTERVAL '10 minutes' THEN
        RETURN FALSE;
    END IF;

    UPDATE private.install_key_secrets AS secret
    SET claim_token_hash = p_claim_token_hash,
        claim_expires_at = p_claim_expires_at,
        claimed_at = NULL
    FROM public.install_key_records AS key_record
    WHERE secret.key_id = p_key_id
      AND secret.owner_key = p_owner_key
      AND key_record.key_id = secret.key_id
      AND key_record.owner_key = p_owner_key
      AND key_record.program = p_program
      AND key_record.active IS TRUE
      AND key_record.payment_status = 'paid'
      AND key_record.entitlements_status = 'active'
      AND key_record.issued_after_payment IS TRUE
      AND (secret.expires_at IS NULL OR secret.expires_at > NOW());

    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    RETURN affected_rows = 1;
END;
$$;

CREATE OR REPLACE FUNCTION public.redeem_install_key_claim(
    p_claim_token_hash TEXT
)
RETURNS TABLE (
    key_id TEXT,
    owner_key TEXT,
    program TEXT,
    key_version TEXT,
    encrypted_key_base64 TEXT
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public, private
AS $$
    UPDATE private.install_key_secrets AS secret
    SET claim_token_hash = NULL,
        claim_expires_at = NULL,
        claimed_at = NOW()
    FROM public.install_key_records AS key_record
    WHERE secret.claim_token_hash = p_claim_token_hash
      AND secret.claim_expires_at > NOW()
      AND (secret.expires_at IS NULL OR secret.expires_at > NOW())
      AND key_record.key_id = secret.key_id
      AND key_record.owner_key = secret.owner_key
      AND key_record.active IS TRUE
      AND key_record.payment_status = 'paid'
      AND key_record.entitlements_status = 'active'
      AND key_record.issued_after_payment IS TRUE
    RETURNING
        secret.key_id,
        secret.owner_key,
        key_record.program,
        secret.key_version,
        encode(secret.encrypted_key, 'base64');
$$;

REVOKE ALL ON FUNCTION public.store_install_key_secret(TEXT, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.issue_install_key_record_with_secret(JSONB, TEXT, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.issue_install_key_claim(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.redeem_install_key_claim(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.issue_install_key_record_with_secret(JSONB, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.store_install_key_secret(TEXT, TEXT, TEXT, TEXT, TEXT) TO service_role;
GRANT EXECUTE ON FUNCTION public.issue_install_key_claim(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ) TO service_role;
GRANT EXECUTE ON FUNCTION public.redeem_install_key_claim(TEXT) TO service_role;
