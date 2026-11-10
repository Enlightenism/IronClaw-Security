-- =============================================================================
-- 008_api_keys_and_auth.sql
-- IronClaw API key table, lookup index, and trigger.
-- Depends on: 001initialpersistenceschema.sql (set_updated_at, pgcrypto)
--             004ironclawinternaltables.sql    (tenants table)
--             005_ironclaw_rls_policies.sql    (RLS for api_keys owned exclusively
--                                              by 005)
-- key_hash stores the SHA-256 hex digest of the raw key (never the raw key).
-- key_prefix stores the first 8 chars of the raw key for display/lookup hints.
-- Revocation is soft via revoked = TRUE; expired keys are enforced at app layer
-- by comparing expires_at against NOW() at request time.
-- NOTE: RLS for api_keys is owned exclusively by 005_ironclaw_rls_policies.sql.
-- =============================================================================


BEGIN;


-- ---------------------------------------------------------------------------
-- api_keys
-- ---------------------------------------------------------------------------


CREATE TABLE IF NOT EXISTS public.api_keys (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash      TEXT        NOT NULL UNIQUE,
    key_prefix    TEXT        NOT NULL DEFAULT '',
    tenant_id     UUID        REFERENCES public.tenants(id) ON DELETE CASCADE,
    created_by    TEXT        NOT NULL DEFAULT 'system',
    scopes        JSONB       NOT NULL DEFAULT '[]'::JSONB,
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    revoked       BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    CONSTRAINT api_keys_key_hash_format_check
        CHECK (key_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT api_keys_key_prefix_length_check
        CHECK (char_length(key_prefix) <= 16),
    CONSTRAINT api_keys_scopes_is_array_check
        CHECK (jsonb_typeof(scopes) = 'array')
);


-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------


-- Primary lookup path: authenticate incoming key by hash
CREATE UNIQUE INDEX IF NOT EXISTS api_key_lookup
    ON public.api_keys (key_hash);


-- Filter active (non-revoked, non-expired) keys per tenant
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id
    ON public.api_keys (tenant_id);


CREATE INDEX IF NOT EXISTS idx_api_keys_revoked
    ON public.api_keys (revoked)
    WHERE revoked = FALSE;


CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at
    ON public.api_keys (expires_at)
    WHERE expires_at IS NOT NULL;


CREATE INDEX IF NOT EXISTS idx_api_keys_created_by
    ON public.api_keys (created_by);


CREATE INDEX IF NOT EXISTS idx_api_keys_created_at
    ON public.api_keys (created_at DESC);


-- ---------------------------------------------------------------------------
-- updated_at trigger
-- ---------------------------------------------------------------------------


CREATE OR REPLACE TRIGGER set_api_keys_updated_at
    BEFORE UPDATE ON public.api_keys
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


-- ---------------------------------------------------------------------------
-- Migration record
-- ---------------------------------------------------------------------------


INSERT INTO public.persistence_migrations (
    migration_key,
    description,
    applied_by,
    checksum,
    metadata
)
VALUES (
    '008_api_keys_and_auth',
    'Creates api_keys table with key_hash (SHA-256), key_prefix, tenant_id FK, '
    'scopes JSONB, expiry, revocation, and last_used_at. Adds api_key_lookup unique '
    'index on key_hash plus supporting indexes. '
    'RLS for api_keys is owned exclusively by 005_ironclaw_rls_policies.sql.',
    'system',
    'seed-v1.0-sha256-placeholder',
    jsonb_build_object(
        'section',       'auth_and_access_control',
        'depends_on',    jsonb_build_array(
                             '001_initial_persistence_schema',
                             '004_ironclaw_internal_tables',
                             '005_ironclaw_rls_policies'
                         ),
        'anon_access',   FALSE
    )
)
ON CONFLICT (migration_key) DO NOTHING;


COMMIT;
