CREATE TABLE IF NOT EXISTS public.stripe_checkout_fulfillments (
    session_id TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL,
    org_id TEXT NOT NULL,
    package_id TEXT NOT NULL,
    units BIGINT NOT NULL CHECK (units > 0),
    payment_intent TEXT UNIQUE,
    customer_id TEXT,
    save_card BOOLEAN NOT NULL DEFAULT FALSE,
    payment_status TEXT NOT NULL DEFAULT 'pending',
    fulfillment_status TEXT NOT NULL DEFAULT 'pending',
    units_credited BOOLEAN NOT NULL DEFAULT FALSE,
    install_keys_provisioned BOOLEAN NOT NULL DEFAULT FALSE,
    refunded_at TIMESTAMPTZ,
    refund_reason TEXT,
    last_error TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT stripe_checkout_fulfillments_session_id_check
        CHECK (session_id ~ '^cs_[A-Za-z0-9_]+$'),
    CONSTRAINT stripe_checkout_fulfillments_owner_key_check
        CHECK (char_length(btrim(owner_key)) > 0),
    CONSTRAINT stripe_checkout_fulfillments_org_id_check
        CHECK (char_length(btrim(org_id)) > 0),
    CONSTRAINT stripe_checkout_fulfillments_package_id_check
        CHECK (char_length(btrim(package_id)) > 0),
    CONSTRAINT stripe_checkout_fulfillments_status_check
        CHECK (fulfillment_status IN ('pending', 'payment_confirmed', 'wallet_credited', 'fulfilled', 'refunded', 'failed'))
);

CREATE INDEX IF NOT EXISTS stripe_checkout_fulfillments_owner_created_idx
    ON public.stripe_checkout_fulfillments (owner_key, created_at DESC);

CREATE TABLE IF NOT EXISTS public.stripe_payment_refund_markers (
    payment_intent TEXT PRIMARY KEY,
    charge_id TEXT,
    amount_refunded BIGINT NOT NULL CHECK (amount_refunded > 0),
    refund_reason TEXT NOT NULL DEFAULT 'charge_refunded',
    refunded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    CONSTRAINT stripe_payment_refund_markers_payment_intent_check
        CHECK (payment_intent ~ '^pi_[A-Za-z0-9_]+$')
);

ALTER TABLE public.stripe_checkout_fulfillments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.stripe_payment_refund_markers ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.stripe_checkout_fulfillments FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.stripe_payment_refund_markers FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.stripe_checkout_fulfillments TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.stripe_payment_refund_markers TO service_role;

CREATE OR REPLACE FUNCTION public.register_stripe_checkout_fulfillment(
    p_session_id TEXT,
    p_owner_key TEXT,
    p_org_id TEXT,
    p_package_id TEXT,
    p_units BIGINT,
    p_payment_intent TEXT,
    p_customer_id TEXT,
    p_save_card BOOLEAN,
    p_metadata JSONB
)
RETURNS SETOF public.stripe_checkout_fulfillments
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    fulfillment public.stripe_checkout_fulfillments%ROWTYPE;
    normalized_payment_intent TEXT := NULLIF(btrim(p_payment_intent), '');
BEGIN
    IF p_session_id IS NULL OR p_session_id !~ '^cs_[A-Za-z0-9_]+$'
       OR p_owner_key IS NULL OR btrim(p_owner_key) = ''
       OR p_org_id IS NULL OR btrim(p_org_id) = ''
       OR p_package_id IS NULL OR btrim(p_package_id) = ''
       OR p_units IS NULL OR p_units <= 0
       OR (normalized_payment_intent IS NOT NULL AND normalized_payment_intent !~ '^pi_[A-Za-z0-9_]+$') THEN
        RAISE EXCEPTION 'invalid Stripe checkout fulfillment arguments';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext(p_session_id));
    IF normalized_payment_intent IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext(normalized_payment_intent));
    END IF;

    SELECT *
    INTO fulfillment
    FROM public.stripe_checkout_fulfillments AS existing
    WHERE existing.session_id = p_session_id
    FOR UPDATE;

    IF FOUND THEN
        IF fulfillment.owner_key IS DISTINCT FROM lower(btrim(p_owner_key))
           OR fulfillment.org_id IS DISTINCT FROM lower(btrim(p_org_id))
           OR fulfillment.package_id IS DISTINCT FROM btrim(p_package_id)
           OR fulfillment.units IS DISTINCT FROM p_units
           OR (fulfillment.payment_intent IS NOT NULL
               AND normalized_payment_intent IS NOT NULL
               AND fulfillment.payment_intent IS DISTINCT FROM normalized_payment_intent) THEN
            RAISE EXCEPTION 'Stripe checkout session is already bound to different fulfillment data';
        END IF;

        IF (normalized_payment_intent IS NOT NULL
            AND EXISTS (
                SELECT 1 FROM public.stripe_payment_refund_markers AS marker
                WHERE marker.payment_intent = normalized_payment_intent
            )) OR (fulfillment.payment_intent IS NOT NULL
                   AND EXISTS (
                       SELECT 1 FROM public.stripe_payment_refund_markers AS marker
                       WHERE marker.payment_intent = fulfillment.payment_intent
                   )) THEN
            UPDATE public.stripe_checkout_fulfillments AS existing
            SET payment_intent = COALESCE(existing.payment_intent, normalized_payment_intent),
                customer_id = COALESCE(NULLIF(p_customer_id, ''), existing.customer_id),
                payment_status = 'refunded',
                fulfillment_status = 'refunded',
                refunded_at = COALESCE(existing.refunded_at, now()),
                refund_reason = COALESCE(existing.refund_reason, 'charge_refunded'),
                updated_at = now()
            WHERE existing.session_id = p_session_id
            RETURNING existing.* INTO fulfillment;
        ELSE
            UPDATE public.stripe_checkout_fulfillments AS existing
            SET payment_intent = COALESCE(existing.payment_intent, normalized_payment_intent),
                customer_id = COALESCE(NULLIF(p_customer_id, ''), existing.customer_id),
                save_card = existing.save_card OR COALESCE(p_save_card, FALSE),
                metadata = existing.metadata || COALESCE(p_metadata, '{}'::JSONB),
                updated_at = now()
            WHERE existing.session_id = p_session_id
            RETURNING existing.* INTO fulfillment;
        END IF;

        RETURN NEXT fulfillment;
        RETURN;
    END IF;

    INSERT INTO public.stripe_checkout_fulfillments (
        session_id,
        owner_key,
        org_id,
        package_id,
        units,
        payment_intent,
        customer_id,
        save_card,
        payment_status,
        fulfillment_status,
        refunded_at,
        refund_reason,
        metadata
    )
    VALUES (
        p_session_id,
        lower(btrim(p_owner_key)),
        lower(btrim(p_org_id)),
        btrim(p_package_id),
        p_units,
        normalized_payment_intent,
        NULLIF(p_customer_id, ''),
        COALESCE(p_save_card, FALSE),
        CASE WHEN normalized_payment_intent IS NOT NULL
                  AND EXISTS (
                      SELECT 1 FROM public.stripe_payment_refund_markers AS marker
                      WHERE marker.payment_intent = normalized_payment_intent
                  )
             THEN 'refunded' ELSE 'pending' END,
        CASE WHEN normalized_payment_intent IS NOT NULL
                  AND EXISTS (
                      SELECT 1 FROM public.stripe_payment_refund_markers AS marker
                      WHERE marker.payment_intent = normalized_payment_intent
                  )
             THEN 'refunded' ELSE 'pending' END,
        CASE WHEN normalized_payment_intent IS NOT NULL
                  AND EXISTS (
                      SELECT 1 FROM public.stripe_payment_refund_markers AS marker
                      WHERE marker.payment_intent = normalized_payment_intent
                  )
             THEN now() ELSE NULL END,
        CASE WHEN normalized_payment_intent IS NOT NULL
                  AND EXISTS (
                      SELECT 1 FROM public.stripe_payment_refund_markers AS marker
                      WHERE marker.payment_intent = normalized_payment_intent
                  )
             THEN 'charge_refunded' ELSE NULL END,
        COALESCE(p_metadata, '{}'::JSONB)
    )
    RETURNING * INTO fulfillment;

    RETURN NEXT fulfillment;
END;
$$;

CREATE OR REPLACE FUNCTION public.record_stripe_payment_refund(
    p_payment_intent TEXT,
    p_charge_id TEXT,
    p_amount_refunded BIGINT,
    p_refund_reason TEXT,
    p_refunded_at TIMESTAMPTZ,
    p_metadata JSONB
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_payment_intent IS NULL OR p_payment_intent !~ '^pi_[A-Za-z0-9_]+$'
       OR p_amount_refunded IS NULL OR p_amount_refunded <= 0 THEN
        RAISE EXCEPTION 'invalid Stripe refund marker arguments';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext(p_payment_intent));

    INSERT INTO public.stripe_payment_refund_markers (
        payment_intent, charge_id, amount_refunded, refund_reason, refunded_at, metadata
    )
    VALUES (
        p_payment_intent,
        NULLIF(p_charge_id, ''),
        p_amount_refunded,
        COALESCE(NULLIF(p_refund_reason, ''), 'charge_refunded'),
        COALESCE(p_refunded_at, now()),
        COALESCE(p_metadata, '{}'::JSONB)
    )
    ON CONFLICT (payment_intent) DO UPDATE
    SET charge_id = COALESCE(EXCLUDED.charge_id, public.stripe_payment_refund_markers.charge_id),
        amount_refunded = GREATEST(public.stripe_payment_refund_markers.amount_refunded, EXCLUDED.amount_refunded),
        refund_reason = EXCLUDED.refund_reason,
        refunded_at = LEAST(public.stripe_payment_refund_markers.refunded_at, EXCLUDED.refunded_at),
        metadata = public.stripe_payment_refund_markers.metadata || EXCLUDED.metadata;

    UPDATE public.stripe_checkout_fulfillments
    SET payment_status = 'refunded',
        fulfillment_status = 'refunded',
        refunded_at = COALESCE(refunded_at, p_refunded_at, now()),
        refund_reason = COALESCE(NULLIF(p_refund_reason, ''), 'charge_refunded'),
        updated_at = now()
    WHERE payment_intent = p_payment_intent;
END;
$$;

CREATE OR REPLACE FUNCTION public.mark_stripe_checkout_fulfillment(
    p_session_id TEXT,
    p_fulfillment_status TEXT,
    p_units_credited BOOLEAN,
    p_install_keys_provisioned BOOLEAN,
    p_last_error TEXT,
    p_metadata JSONB
)
RETURNS SETOF public.stripe_checkout_fulfillments
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    payment_intent_value TEXT;
    fulfillment public.stripe_checkout_fulfillments%ROWTYPE;
BEGIN
    IF p_session_id IS NULL OR btrim(p_session_id) = ''
       OR p_fulfillment_status NOT IN ('pending', 'payment_confirmed', 'wallet_credited', 'fulfilled', 'refunded', 'failed') THEN
        RAISE EXCEPTION 'invalid Stripe checkout fulfillment status arguments';
    END IF;

    SELECT record.payment_intent
    INTO payment_intent_value
    FROM public.stripe_checkout_fulfillments AS record
    WHERE record.session_id = p_session_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Stripe checkout fulfillment record not found';
    END IF;
    IF payment_intent_value IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtext(payment_intent_value));
    END IF;

    SELECT *
    INTO fulfillment
    FROM public.stripe_checkout_fulfillments AS record
    WHERE record.session_id = p_session_id
    FOR UPDATE;

    IF fulfillment.refunded_at IS NOT NULL
       OR (payment_intent_value IS NOT NULL
           AND EXISTS (
               SELECT 1 FROM public.stripe_payment_refund_markers AS marker
               WHERE marker.payment_intent = payment_intent_value
           )) THEN
        UPDATE public.stripe_checkout_fulfillments AS record
        SET payment_status = 'refunded',
            fulfillment_status = 'refunded',
            refunded_at = COALESCE(record.refunded_at, now()),
            refund_reason = COALESCE(record.refund_reason, 'charge_refunded'),
            updated_at = now()
        WHERE record.session_id = p_session_id
        RETURNING record.* INTO fulfillment;
        RETURN NEXT fulfillment;
        RETURN;
    END IF;

    UPDATE public.stripe_checkout_fulfillments AS record
    SET payment_status = CASE
            WHEN p_fulfillment_status IN ('payment_confirmed', 'wallet_credited', 'fulfilled') THEN 'paid'
            ELSE record.payment_status
        END,
        fulfillment_status = p_fulfillment_status,
        units_credited = COALESCE(p_units_credited, record.units_credited),
        install_keys_provisioned = COALESCE(p_install_keys_provisioned, record.install_keys_provisioned),
        last_error = p_last_error,
        metadata = record.metadata || COALESCE(p_metadata, '{}'::JSONB),
        updated_at = now()
    WHERE record.session_id = p_session_id
    RETURNING record.* INTO fulfillment;

    RETURN NEXT fulfillment;
END;
$$;

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
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    existing_entry public.unit_ledger%ROWTYPE;
    wallet_record public.unit_wallets%ROWTYPE;
    fulfillment public.stripe_checkout_fulfillments%ROWTYPE;
    normalized_metadata JSONB := COALESCE(p_metadata, '{}'::JSONB);
    payment_intent_value TEXT := NULLIF(btrim(COALESCE(p_metadata, '{}'::JSONB) ->> 'payment_intent'), '');
    package_id_value TEXT := NULLIF(btrim(COALESCE(p_metadata, '{}'::JSONB) ->> 'package_id'), '');
BEGIN
    IF p_wallet_id IS NULL OR btrim(p_wallet_id) = ''
       OR p_owner_key IS NULL OR btrim(p_owner_key) = ''
       OR p_entry_id IS NULL OR btrim(p_entry_id) = ''
       OR p_units IS NULL OR p_units < 0 THEN
        RAISE EXCEPTION 'invalid wallet credit arguments';
    END IF;

    IF p_checkout_session_id IS NOT NULL
       AND p_event_id = 'stripe:checkout_complete:' || btrim(p_checkout_session_id) THEN
        IF payment_intent_value IS NULL OR payment_intent_value !~ '^pi_[A-Za-z0-9_]+$'
           OR package_id_value IS NULL THEN
            RAISE EXCEPTION 'Stripe checkout credit is missing its PaymentIntent or package association';
        END IF;

        PERFORM pg_advisory_xact_lock(hashtext(payment_intent_value));

        SELECT *
        INTO fulfillment
        FROM public.stripe_checkout_fulfillments AS record
        WHERE record.session_id = p_checkout_session_id
        FOR UPDATE;

        IF NOT FOUND
           OR fulfillment.owner_key IS DISTINCT FROM lower(btrim(p_owner_key))
           OR fulfillment.units IS DISTINCT FROM p_units
           OR fulfillment.package_id IS DISTINCT FROM package_id_value
           OR fulfillment.payment_intent IS DISTINCT FROM payment_intent_value THEN
            RAISE EXCEPTION 'Stripe checkout fulfillment record does not match the wallet credit';
        END IF;

        IF fulfillment.refunded_at IS NOT NULL
           OR EXISTS (
               SELECT 1 FROM public.stripe_payment_refund_markers AS marker
               WHERE marker.payment_intent = payment_intent_value
           ) THEN
            RAISE EXCEPTION 'Stripe checkout payment has been refunded';
        END IF;
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
        entry_id, wallet_id, owner_key, entry_type, units, balance_after,
        created_at, purchase_id, checkout_session_id, event_id, metadata
    )
    VALUES (
        p_entry_id, wallet_record.wallet_id, p_owner_key, 'credit', p_units,
        wallet_record.balance_units, COALESCE(p_created_at, now()), p_purchase_id,
        p_checkout_session_id, NULLIF(p_event_id, ''), normalized_metadata
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

REVOKE ALL ON FUNCTION public.register_stripe_checkout_fulfillment(
    TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BOOLEAN, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.register_stripe_checkout_fulfillment(
    TEXT, TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, BOOLEAN, JSONB
) TO service_role;

REVOKE ALL ON FUNCTION public.record_stripe_payment_refund(
    TEXT, TEXT, BIGINT, TEXT, TIMESTAMPTZ, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_stripe_payment_refund(
    TEXT, TEXT, BIGINT, TEXT, TIMESTAMPTZ, JSONB
) TO service_role;

REVOKE ALL ON FUNCTION public.mark_stripe_checkout_fulfillment(
    TEXT, TEXT, BOOLEAN, BOOLEAN, TEXT, JSONB
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_stripe_checkout_fulfillment(
    TEXT, TEXT, BOOLEAN, BOOLEAN, TEXT, JSONB
) TO service_role;

REVOKE ALL ON FUNCTION public.credit_unit_wallet_once(
    TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.credit_unit_wallet_once(
    TEXT, TEXT, TEXT, BIGINT, TEXT, TEXT, TEXT, JSONB, TIMESTAMPTZ
) TO service_role;
