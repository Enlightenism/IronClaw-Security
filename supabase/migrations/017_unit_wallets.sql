-- Persist unit wallets and their ledger so paid units survive process restarts and
-- are visible to every worker. The registry in app/core/unit_wallet.py reads and
-- writes these tables with the service role only.

CREATE TABLE IF NOT EXISTS public.unit_wallets (
    wallet_id TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL UNIQUE,
    balance_units BIGINT NOT NULL DEFAULT 0,
    total_purchased_units BIGINT NOT NULL DEFAULT 0,
    total_consumed_units BIGINT NOT NULL DEFAULT 0,
    total_refunded_units BIGINT NOT NULL DEFAULT 0,
    total_blocked_attacks BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.unit_ledger (
    entry_id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES public.unit_wallets (wallet_id) ON DELETE CASCADE,
    owner_key TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    units BIGINT NOT NULL,
    balance_after BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    purchase_id TEXT,
    checkout_session_id TEXT,
    event_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS unit_ledger_owner_key_created_at_idx
    ON public.unit_ledger (owner_key, created_at DESC);
CREATE INDEX IF NOT EXISTS unit_ledger_event_id_idx
    ON public.unit_ledger (event_id);
CREATE INDEX IF NOT EXISTS unit_ledger_checkout_session_id_idx
    ON public.unit_ledger (checkout_session_id);

ALTER TABLE public.unit_wallets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.unit_ledger ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.unit_wallets FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE public.unit_ledger FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE ON TABLE public.unit_wallets TO service_role;
GRANT SELECT, INSERT, UPDATE ON TABLE public.unit_ledger TO service_role;
