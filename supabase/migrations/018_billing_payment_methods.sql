-- Org-to-saved-payment-method links for the dashboard's saved-card panel. Card data is
-- redacted: only brand, last4, and expiry are stored, never full card numbers.
-- The service role reads and writes this table; anon and authenticated have no access.

CREATE TABLE IF NOT EXISTS public.billing_payment_methods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id TEXT NOT NULL,
    stripe_payment_method_id TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'card',
    brand TEXT NOT NULL DEFAULT 'unknown',
    last4 TEXT NOT NULL DEFAULT '',
    exp_month INTEGER NOT NULL DEFAULT 0,
    exp_year INTEGER NOT NULL DEFAULT 0,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT billing_payment_methods_org_method_key UNIQUE (organization_id, stripe_payment_method_id)
);

CREATE INDEX IF NOT EXISTS billing_payment_methods_organization_id_idx
    ON public.billing_payment_methods (organization_id);

ALTER TABLE public.billing_payment_methods ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.billing_payment_methods FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.billing_payment_methods TO service_role;
