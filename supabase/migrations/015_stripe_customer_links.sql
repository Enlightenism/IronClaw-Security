-- Persist the organization-to-Stripe-customer link so saved payment methods, invoices,
-- and duplicate-customer protection survive process restarts. Only the service role
-- reads or writes this table; it holds no card data.

CREATE TABLE IF NOT EXISTS public.stripe_customer_links (
    org_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.stripe_customer_links ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.stripe_customer_links FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.stripe_customer_links TO service_role;
