CREATE OR REPLACE FUNCTION public.credit_unit_wallet_once(
    p_wallet_id TEXT,
    p_owner_key TEXT,
    p_entry_id TEXT,
    p_units BIGINT,
    p_purchase_id TEXT,
    p_checkout_session_id TEXT,
    p_event_id TEXT,
    p_metadata JSONB,
    p_created_at TIMESTAMPTZ
)
RETURNS TABLE (
    applied BOOLEAN,
    wallet_id TEXT,
    owner_key TEXT,
    balance_units BIGINT,
    total_purchased_units BIGINT,
    total_consumed_units BIGINT,
    total_refunded_units BIGINT,
    total_blocked_attacks BIGINT,
    updated_at TIMESTAMPTZ,
    metadata JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    existing_entry public.unit_ledger%ROWTYPE;
    wallet_record public.unit_wallets%ROWTYPE;
    normalized_metadata JSONB := COALESCE(p_metadata, '{}'::JSONB);
BEGIN
    IF p_wallet_id IS NULL OR btrim(p_wallet_id) = ''
       OR p_owner_key IS NULL OR btrim(p_owner_key) = ''
       OR p_entry_id IS NULL OR btrim(p_entry_id) = ''
       OR p_units IS NULL OR p_units < 0 THEN
        RAISE EXCEPTION 'invalid wallet credit arguments';
    END IF;

    IF p_event_id IS NOT NULL AND btrim(p_event_id) <> '' THEN
        PERFORM pg_advisory_xact_lock(hashtext(p_event_id));

        SELECT *
        INTO existing_entry
        FROM public.unit_ledger
        WHERE event_id = p_event_id
        LIMIT 1;

        IF FOUND THEN
            IF existing_entry.owner_key IS DISTINCT FROM p_owner_key
               OR existing_entry.entry_type IS DISTINCT FROM 'credit'
               OR existing_entry.units IS DISTINCT FROM p_units
               OR existing_entry.checkout_session_id IS DISTINCT FROM p_checkout_session_id
               OR (existing_entry.metadata ->> 'package_id')
                    IS DISTINCT FROM (normalized_metadata ->> 'package_id') THEN
                RAISE EXCEPTION 'event_id is already associated with a different wallet operation';
            END IF;

            SELECT *
            INTO wallet_record
            FROM public.unit_wallets AS wallet
            WHERE wallet.owner_key = p_owner_key;

            IF NOT FOUND THEN
                RAISE EXCEPTION 'wallet missing for previously credited event';
            END IF;

            RETURN QUERY
            SELECT
                FALSE,
                wallet_record.wallet_id,
                wallet_record.owner_key,
                wallet_record.balance_units,
                wallet_record.total_purchased_units,
                wallet_record.total_consumed_units,
                wallet_record.total_refunded_units,
                wallet_record.total_blocked_attacks,
                wallet_record.updated_at,
                wallet_record.metadata;
            RETURN;
        END IF;
    END IF;

    INSERT INTO public.unit_wallets (wallet_id, owner_key)
    VALUES (p_wallet_id, p_owner_key)
    ON CONFLICT (owner_key) DO NOTHING;

    SELECT *
    INTO wallet_record
    FROM public.unit_wallets AS wallet
    WHERE wallet.owner_key = p_owner_key
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'wallet could not be created for owner';
    END IF;

    UPDATE public.unit_wallets AS wallet
    SET balance_units = wallet_record.balance_units + p_units,
        total_purchased_units = wallet_record.total_purchased_units + p_units,
        updated_at = COALESCE(p_created_at, now())
    WHERE wallet.owner_key = p_owner_key
    RETURNING wallet.* INTO wallet_record;

    INSERT INTO public.unit_ledger (
        entry_id,
        wallet_id,
        owner_key,
        entry_type,
        units,
        balance_after,
        created_at,
        purchase_id,
        checkout_session_id,
        event_id,
        metadata
    )
    VALUES (
        p_entry_id,
        wallet_record.wallet_id,
        p_owner_key,
        'credit',
        p_units,
        wallet_record.balance_units,
        COALESCE(p_created_at, now()),
        p_purchase_id,
        p_checkout_session_id,
        NULLIF(p_event_id, ''),
        normalized_metadata
    );

    RETURN QUERY
    SELECT
        TRUE,
        wallet_record.wallet_id,
        wallet_record.owner_key,
        wallet_record.balance_units,
        wallet_record.total_purchased_units,
        wallet_record.total_consumed_units,
        wallet_record.total_refunded_units,
        wallet_record.total_blocked_attacks,
        wallet_record.updated_at,
        wallet_record.metadata;
END;
$$;

REVOKE ALL ON FUNCTION public.credit_unit_wallet_once(
    TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.credit_unit_wallet_once(
    TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ
) TO service_role;
