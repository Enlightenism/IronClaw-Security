-- =============================================================================
-- 007_seed_default_policy_set.sql
-- IronClaw default policy set seed
-- Creates the policy_sets table and inserts the ironclaw_default row.
-- This row becomes the system-wide fallback policy when no tenant-specific
-- policy set is found. It references all builtin policy_rules from 006 by
-- rule_id. enforcement_mode = 'block', severity thresholds, and sandbox lane
-- mappings are stored as structured JSONB.
-- Depends on: 006_seed_ioc_patterns.sql (policy_rules table + rule_id seeds)
-- =============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- policy_sets
-- One row per named policy configuration. The ironclaw_default row is the
-- system fallback. Tenant rows reference the same table with a different
-- set_key and may override rule_ids and thresholds.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.policy_sets (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    set_key               TEXT        NOT NULL UNIQUE,
    display_name          TEXT        NOT NULL DEFAULT '',
    description           TEXT        NOT NULL DEFAULT '',
    is_builtin            BOOLEAN     NOT NULL DEFAULT FALSE,
    is_default            BOOLEAN     NOT NULL DEFAULT FALSE,
    enforcement_mode      TEXT        NOT NULL DEFAULT 'block',
    -- policy_rule_ids: ordered array of rule_id values from policy_rules table
    -- that this set enforces. Used by the policy engine to load rules at runtime.
    policy_rule_ids       JSONB       NOT NULL DEFAULT '[]'::JSONB,
    -- severity_thresholds: maps severity level → enforcement action override
    -- e.g. {"critical": "block", "high": "block", "medium": "review", "low": "warn"}
    severity_thresholds   JSONB       NOT NULL DEFAULT '{}'::JSONB,
    -- sandbox_lane_mappings: maps sandbox execution lane → max allowed verdict
    -- e.g. {"restricted": "block", "elevated": "review", "trusted": "allow"}
    sandbox_lane_mappings JSONB       NOT NULL DEFAULT '{}'::JSONB,
    -- extra_config: open-ended policy metadata (rate limits, quarantine TTL, etc.)
    extra_config          JSONB       NOT NULL DEFAULT '{}'::JSONB,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    CONSTRAINT policy_sets_enforcement_mode_check
        CHECK (enforcement_mode IN ('block', 'review', 'warn', 'audit')),
    CONSTRAINT policy_sets_one_default
        EXCLUDE USING btree (is_default WITH =) WHERE (is_default = TRUE)
);

CREATE INDEX IF NOT EXISTS idx_policy_sets_set_key     ON public.policy_sets (set_key);
CREATE INDEX IF NOT EXISTS idx_policy_sets_is_builtin  ON public.policy_sets (is_builtin);
CREATE INDEX IF NOT EXISTS idx_policy_sets_is_default  ON public.policy_sets (is_default);

CREATE TRIGGER set_policy_sets_updated_at
    BEFORE UPDATE ON public.policy_sets
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ---------------------------------------------------------------------------
-- policy_set_memberships
-- Junction table linking a policy_set to individual policy_rules rows.
-- Allows ordered, priority-aware rule membership per set without mutating
-- the policy_rules table. The policy_rule_ids JSONB on policy_sets is the
-- fast-path cache; this table is the relational source of truth.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.policy_set_memberships (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_set_id   UUID        NOT NULL REFERENCES public.policy_sets(id) ON DELETE CASCADE,
    policy_rule_id  UUID        NOT NULL REFERENCES public.policy_rules(id) ON DELETE CASCADE,
    rule_id         TEXT        NOT NULL,
    sort_order      INTEGER     NOT NULL DEFAULT 0,
    override_verdict TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', NOW()),
    CONSTRAINT policy_set_memberships_unique_rule
        UNIQUE (policy_set_id, policy_rule_id),
    CONSTRAINT policy_set_memberships_override_verdict_check
        CHECK (override_verdict IS NULL OR override_verdict IN ('allow', 'review', 'block', 'warn'))
);

CREATE INDEX IF NOT EXISTS idx_psm_policy_set_id  ON public.policy_set_memberships (policy_set_id);
CREATE INDEX IF NOT EXISTS idx_psm_policy_rule_id ON public.policy_set_memberships (policy_rule_id);
CREATE INDEX IF NOT EXISTS idx_psm_rule_id        ON public.policy_set_memberships (rule_id);
CREATE INDEX IF NOT EXISTS idx_psm_sort_order     ON public.policy_set_memberships (policy_set_id, sort_order);

-- ---------------------------------------------------------------------------
-- SEED: ironclaw_default policy set
-- Single canonical row; is_default = TRUE enforced by partial unique exclude.
-- All builtin rule_ids from 006_seed_ioc_patterns are listed in
-- policy_rule_ids for fast-path loading. enforcement_mode = 'block'.
-- ---------------------------------------------------------------------------

INSERT INTO public.policy_sets (
    set_key,
    display_name,
    description,
    is_builtin,
    is_default,
    enforcement_mode,
    policy_rule_ids,
    severity_thresholds,
    sandbox_lane_mappings,
    extra_config
)
VALUES (
    'ironclaw_default',
    'IronClaw Default Policy Set',
    'System-wide fallback policy enforced when no tenant-specific policy set is found. '
    'Enforces all builtin block, review, and trust-collapse rules with enforcement_mode = block. '
    'Severity thresholds and sandbox lane mappings are production-hardened defaults.',
    TRUE,
    TRUE,
    'block',
    -- policy_rule_ids: all builtin rule_ids from 006 in priority order
    -- Priority bands: trust_collapse (5) → target_block (10) → target_review (50) → action_review (40)
    jsonb_build_array(
        -- trust_collapse rules (priority 5 — highest, terminate session)
        'trust_collapse_system_prompt_exfil',
        'trust_collapse_data_exfiltration',
        'trust_collapse_multistep_escalation',
        'trust_collapse_retrieved_content_authority',
        'trust_collapse_self_referential_control',
        'trust_collapse_tool_output_authority',
        'trust_collapse_review_bypass',
        'trust_collapse_policy_override_demand',
        'trust_collapse_local_file_discovery',
        -- target_block rules (priority 10 — hard block)
        'block_target_system32',
        'block_target_syswow64',
        'block_target_programdata',
        'block_target_etc',
        'block_target_root_home',
        'block_target_var_run',
        'block_target_ssh_dir',
        'block_target_id_rsa',
        'block_target_id_dsa',
        'block_target_dotenv',
        'block_target_pem',
        'block_target_pfx',
        'block_target_key_file',
        'block_target_secrets',
        'block_target_credential',
        'block_target_token',
        'block_target_passwd',
        'block_target_shadow',
        'block_target_known_hosts',
        'block_target_authorized_keys',
        'block_target_aws_config',
        'block_target_azure_config',
        'block_target_gcloud_config',
        'block_target_kubeconfig',
        -- action_review rules (priority 40 — elevated review gate)
        'review_action_shell_command',
        'review_action_network_request',
        'review_action_git_operation',
        'review_action_file_write',
        'review_action_tool_call',
        -- target_review rules (priority 50 — high-review targets)
        'review_target_powershell',
        'review_target_pwsh',
        'review_target_cmd',
        'review_target_bash',
        'review_target_sh',
        'review_target_zsh',
        'review_target_curl',
        'review_target_wget',
        'review_target_invoke_webrequest',
        'review_target_iwr',
        'review_target_scp',
        'review_target_ssh',
        'review_target_sftp',
        'review_target_ftp',
        'review_target_git',
        'review_target_python',
        'review_target_py',
        'review_target_node',
        'review_target_npm',
        'review_target_npx',
        'review_target_pip',
        'review_target_docker',
        'review_target_kubectl',
        'review_target_az_cli',
        'review_target_aws_cli',
        'review_target_gcloud',
        'review_target_rclone',
        'review_target_certutil',
        'review_target_regsvr32',
        'review_target_mshta',
        'review_target_rundll32'
    ),
    -- severity_thresholds: maps scan_patterns severity → enforcement action
    -- critical and high always block; medium requires review; low warns and audits
    jsonb_build_object(
        'critical', 'block',
        'high',     'block',
        'medium',   'review',
        'low',      'warn'
    ),
    -- sandbox_lane_mappings: maps execution trust lane → maximum permitted verdict
    -- restricted: full block enforcement (untrusted external content)
    -- elevated:   review gate required (privileged but supervised operations)
    -- trusted:    audit-only (internally validated, pre-approved pipelines)
    jsonb_build_object(
        'restricted', 'block',
        'elevated',   'review',
        'trusted',    'audit'
    ),
    -- extra_config: operational tuning defaults
    jsonb_build_object(
        'max_risk_score_allow',      0.30,
        'max_risk_score_review',     0.65,
        'quarantine_ttl_hours',      72,
        'review_timeout_minutes',    30,
        'trust_collapse_auto_block', TRUE,
        'pii_scan_enabled',          TRUE,
        'prompt_injection_scan_enabled', TRUE,
        'shell_scan_enabled',        TRUE,
        'exfiltration_scan_enabled', TRUE,
        'audit_all_verdicts',        TRUE,
        'schema_version',            '1.0'
    )
)
ON CONFLICT (set_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- SEED: policy_set_memberships for ironclaw_default
-- Inserts one membership row per policy_rule, resolving rule_id → UUID via
-- subquery against policy_rules. sort_order mirrors the priority bands from
-- policy_rules.priority so the policy engine can ORDER BY sort_order.
-- ---------------------------------------------------------------------------

INSERT INTO public.policy_set_memberships (
    policy_set_id,
    policy_rule_id,
    rule_id,
    sort_order,
    override_verdict
)
SELECT
    ps.id                                                     AS policy_set_id,
    pr.id                                                     AS policy_rule_id,
    pr.rule_id,
    pr.priority                                               AS sort_order,
    NULL                                                      AS override_verdict
FROM public.policy_sets        AS ps
INNER JOIN public.policy_rules       AS pr ON pr.is_builtin = TRUE
WHERE ps.set_key = 'ironclaw_default'
  AND pr.enabled = TRUE
ON CONFLICT (policy_set_id, policy_rule_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- RLS: policy_sets (builtin rows are globally readable; mutations restricted)
-- ---------------------------------------------------------------------------

ALTER TABLE public.policy_sets ENABLE ROW LEVEL SECURITY;

CREATE POLICY policy_sets_select_all
    ON public.policy_sets
    FOR SELECT
    USING (TRUE);

CREATE POLICY policy_sets_service_role_all
    ON public.policy_sets
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- ---------------------------------------------------------------------------
-- RLS: policy_set_memberships
-- ---------------------------------------------------------------------------

ALTER TABLE public.policy_set_memberships ENABLE ROW LEVEL SECURITY;

CREATE POLICY psm_select_all
    ON public.policy_set_memberships
    FOR SELECT
    USING (TRUE);

CREATE POLICY psm_service_role_all
    ON public.policy_set_memberships
    AS PERMISSIVE
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

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
    '007_seed_default_policy_set',
    'Creates policy_sets and policy_set_memberships tables. Seeds the ironclaw_default policy set '
    'referencing all builtin policy_rules from migration 006. Includes enforcement_mode = block, '
    'severity_thresholds (critical/high → block, medium → review, low → warn), sandbox_lane_mappings '
    '(restricted → block, elevated → review, trusted → audit), and operational extra_config defaults. '
    'Applies RLS: SELECT open to all authenticated, mutations restricted to service_role.',
    'system',
    '',
    jsonb_build_object(
        'section',       'detection_and_policy',
        'depends_on',    '006_seed_ioc_patterns',
        'seed_version',  '1.0',
        'default_set',   'ironclaw_default'
    )
)
ON CONFLICT (migration_key) DO NOTHING;

COMMIT;
