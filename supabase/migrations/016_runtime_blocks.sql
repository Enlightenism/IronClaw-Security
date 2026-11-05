-- 016_runtime_blocks.sql
-- Runtime block records: one append-only row per return-gate or install-gate block.
-- Stores reason codes and verdict metadata only. No raw agent content is stored.

CREATE TABLE IF NOT EXISTS public.runtime_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_key TEXT,
    platform TEXT NOT NULL,
    gate TEXT NOT NULL CHECK (gate IN ('return', 'install')),
    reason TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict = 'block'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_runtime_blocks_owner_key_created_at
    ON public.runtime_blocks (owner_key, created_at DESC);

ALTER TABLE public.runtime_blocks ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.runtime_blocks FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.runtime_blocks TO service_role;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'runtime_blocks' AND policyname = 'runtime_blocks_service_role_select'
    ) THEN
        CREATE POLICY runtime_blocks_service_role_select ON public.runtime_blocks
            AS PERMISSIVE FOR SELECT TO service_role USING (TRUE);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public' AND tablename = 'runtime_blocks' AND policyname = 'runtime_blocks_service_role_insert'
    ) THEN
        CREATE POLICY runtime_blocks_service_role_insert ON public.runtime_blocks
            AS PERMISSIVE FOR INSERT TO service_role WITH CHECK (TRUE);
    END IF;
END
$$;
