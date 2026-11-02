-- Install-key claims no longer expire. A claim is still single-use: redeeming it
-- clears claim_token_hash, and the hash must match an active, paid, entitled key.
-- Signatures are unchanged so existing callers keep working.

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
    IF p_claim_token_hash IS NULL OR p_claim_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN FALSE;
    END IF;

    -- p_claim_expires_at is accepted for signature compatibility and intentionally ignored.
    UPDATE private.install_key_secrets AS secret
    SET claim_token_hash = p_claim_token_hash,
        claim_expires_at = NULL,
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
