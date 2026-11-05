-- 015_refund_revocation.sql
-- Refund revocation: map purchases to Stripe payment intents, keep a refund audit trail,
-- and allow unredeemed install-key claim tokens to be revoked when a refund is processed.

ALTER TABLE public.billing_purchases
    ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS refund_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_billing_purchases_stripe_payment_intent_id
    ON public.billing_purchases (stripe_payment_intent_id);

ALTER TABLE public.ironclaw_billing_purchases
    ADD COLUMN IF NOT EXISTS payment_intent TEXT,
    ADD COLUMN IF NOT EXISTS refunded_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS refund_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_ironclaw_billing_purchases_payment_intent
    ON public.ironclaw_billing_purchases (payment_intent);

CREATE OR REPLACE FUNCTION public.revoke_install_key_claims(p_key_id TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, private
AS $$
BEGIN
    UPDATE private.install_key_secrets
    SET claim_token_hash = NULL,
        encrypted_command = NULL
    WHERE key_id = p_key_id;
END;
$$;

REVOKE ALL ON FUNCTION public.revoke_install_key_claims(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_install_key_claims(TEXT) TO service_role;
