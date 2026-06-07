-- =============================================================================
-- 010_threat_feed_tables.sql
-- IronClaw threat intelligence feed tables.
-- Creates:
--   public.ioc_records       — deduplicated IOC store (upsert target)
--   public.feed_ingest_log   — append-only ingest run log
-- Safe to re-run: all DDL uses IF NOT EXISTS guards.
-- =============================================================================

-- =============================================================================
-- SECTION 1 — Types
-- =============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type
        WHERE typname = 'ioc_type'
          AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        CREATE TYPE public.ioc_type AS ENUM (
            'ip',
            'ipv6',
            'domain',
            'url',
            'hash_md5',
            'hash_sha1',
            'hash_sha256',
            'hash_sha512',
            'email',
            'cidr',
            'cve',
            'filename',
            'registry_key',
            'user_agent',
            'other'
        );
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type
        WHERE typname = 'ioc_severity'
          AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        CREATE TYPE public.ioc_severity AS ENUM (
            'info',
            'low',
            'medium',
            'high',
            'critical'
        );
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type
        WHERE typname = 'feed_ingest_status'
          AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')
    ) THEN
        CREATE TYPE public.feed_ingest_status AS ENUM (
            'success',
            'partial',
            'failed',
            'skipped'
        );
    END IF;
END $$;

-- =============================================================================
-- SECTION 2 — ioc_records
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.ioc_records (
    id              UUID                NOT NULL DEFAULT gen_random_uuid(),
    ioc_type        public.IOC_TYPE     NOT NULL,
    ioc_value       TEXT                NOT NULL,
    source_feed     TEXT                NOT NULL,
    feed_format     TEXT                NOT NULL DEFAULT 'unknown',
    confidence      SMALLINT            NOT NULL DEFAULT 50
                        CONSTRAINT ioc_records_confidence_range
                        CHECK (confidence BETWEEN 0 AND 100),
    severity        public.IOC_SEVERITY NOT NULL DEFAULT 'medium',
    tags            TEXT[]              NOT NULL DEFAULT '{}',
    raw_context     JSONB               NOT NULL DEFAULT '{}'::JSONB,
    first_seen_feed TIMESTAMPTZ         NULL,
    last_seen_feed  TIMESTAMPTZ         NULL,
    last_synced_at  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    is_active       BOOLEAN             NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT ioc_records_pkey PRIMARY KEY (id),
    CONSTRAINT ioc_records_type_value_unique UNIQUE (ioc_type, ioc_value)
);

CREATE OR REPLACE FUNCTION public.ioc_records_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'ioc_records_updated_at_trigger'
    ) THEN
        CREATE TRIGGER ioc_records_updated_at_trigger
            BEFORE UPDATE ON public.ioc_records
            FOR EACH ROW
            EXECUTE FUNCTION public.ioc_records_set_updated_at();
    END IF;
END $$;

-- =============================================================================
-- SECTION 3 — feed_ingest_log
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.feed_ingest_log (
    id                  UUID                        NOT NULL DEFAULT gen_random_uuid(),
    run_started_at      TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),
    run_finished_at     TIMESTAMPTZ                 NULL,
    overall_status      public.FEED_INGEST_STATUS   NOT NULL DEFAULT 'failed',
    total_iocs_upserted INTEGER                     NOT NULL DEFAULT 0,
    feeds_processed     INTEGER                     NOT NULL DEFAULT 0,
    feed_results        JSONB                       NOT NULL DEFAULT '[]'::JSONB,

    CONSTRAINT feed_ingest_log_pkey PRIMARY KEY (id)
);

-- =============================================================================
-- SECTION 4 — Indexes: ioc_records
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_ioc_records_type
    ON public.ioc_records (ioc_type);

CREATE INDEX IF NOT EXISTS idx_ioc_records_severity
    ON public.ioc_records (severity);

CREATE INDEX IF NOT EXISTS idx_ioc_records_is_active
    ON public.ioc_records (is_active)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_ioc_records_last_synced_at
    ON public.ioc_records (last_synced_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_records_active_type
    ON public.ioc_records (is_active, ioc_type);

CREATE INDEX IF NOT EXISTS idx_ioc_records_tags_gin
    ON public.ioc_records USING gin (tags);

CREATE INDEX IF NOT EXISTS idx_ioc_records_raw_context_gin
    ON public.ioc_records USING gin (raw_context jsonb_path_ops);

-- =============================================================================
-- SECTION 5 — Indexes: feed_ingest_log
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_run_started_at
    ON public.feed_ingest_log (run_started_at DESC);

CREATE INDEX IF NOT EXISTS idx_feed_ingest_log_overall_status
    ON public.feed_ingest_log (overall_status);

-- =============================================================================
-- SECTION 6 — RLS
-- =============================================================================

ALTER TABLE public.ioc_records     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feed_ingest_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'ioc_records'
          AND policyname = 'ioc_records_service_role_all'
    ) THEN
        CREATE POLICY ioc_records_service_role_all
            ON public.ioc_records
            AS PERMISSIVE
            FOR ALL
            TO service_role
            USING (TRUE)
            WITH CHECK (TRUE);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'ioc_records'
          AND policyname = 'ioc_records_select_authenticated'
    ) THEN
        CREATE POLICY ioc_records_select_authenticated
            ON public.ioc_records
            FOR SELECT
            TO authenticated
            USING (TRUE);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'feed_ingest_log'
          AND policyname = 'feed_ingest_log_service_role_all'
    ) THEN
        CREATE POLICY feed_ingest_log_service_role_all
            ON public.feed_ingest_log
            AS PERMISSIVE
            FOR ALL
            TO service_role
            USING (TRUE)
            WITH CHECK (TRUE);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'feed_ingest_log'
          AND policyname = 'feed_ingest_log_select_authenticated'
    ) THEN
        CREATE POLICY feed_ingest_log_select_authenticated
            ON public.feed_ingest_log
            FOR SELECT
            TO authenticated
            USING (TRUE);
    END IF;
END $$;

-- =============================================================================
-- END 010_threat_feed_tables.sql
-- =============================================================================
