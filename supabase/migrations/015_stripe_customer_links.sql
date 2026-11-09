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

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'stripe_customer_links' AND policyname = 'stripe_customer_links_service_role_select'
    ) THEN
        CREATE POLICY stripe_customer_links_service_role_select ON public.stripe_customer_links
            AS PERMISSIVE FOR SELECT TO service_role USING (TRUE);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'stripe_customer_links' AND policyname = 'stripe_customer_links_service_role_insert'
    ) THEN
        CREATE POLICY stripe_customer_links_service_role_insert ON public.stripe_customer_links
            AS PERMISSIVE FOR INSERT TO service_role WITH CHECK (TRUE);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'stripe_customer_links' AND policyname = 'stripe_customer_links_service_role_update'
    ) THEN
        CREATE POLICY stripe_customer_links_service_role_update ON public.stripe_customer_links
            AS PERMISSIVE FOR UPDATE TO service_role USING (TRUE) WITH CHECK (TRUE);
    END IF;
END
$$;
