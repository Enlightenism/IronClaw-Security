-- Install claims become reusable. A claim returns the current install key for as long as that key is active. Generating a new command replaces the key, which invalidates older claims through the active-key check.

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
SET search_path TO 'pg_catalog', 'public', 'private'
AS $$
    SELECT
        secret.key_id,
        secret.owner_key,
        key_record.program,
        secret.key_version,
        encode(secret.encrypted_key, 'base64')
    FROM private.install_key_secrets AS secret
    JOIN public.install_key_records AS key_record
      ON key_record.key_id = secret.key_id
     AND key_record.owner_key = secret.owner_key
    WHERE secret.claim_token_hash = p_claim_token_hash
      AND (secret.expires_at IS NULL OR secret.expires_at > NOW())
      AND key_record.active IS TRUE
      AND key_record.payment_status = 'paid'
      AND key_record.entitlements_status = 'active'
      AND key_record.issued_after_payment IS TRUE;
$$;
