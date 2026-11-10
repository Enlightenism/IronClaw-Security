-- Auto-generated migration audit.
-- Run this in Supabase SQL Editor.
-- Any row with present = false needs the migration in source applied.

with expected(kind, object_name, source) as (
    values
    ('table', 'analysis_reports', '001initialpersistenceschema.sql'),
    ('table', 'api_keys', '008_api_keys_and_auth.sql'),
    ('table', 'audit_events', '001initialpersistenceschema.sql'),
    ('table', 'backup_policies', '001initialpersistenceschema.sql'),
    ('table', 'backup_runs', '001initialpersistenceschema.sql'),
    ('table', 'billing_payment_methods', '018_billing_payment_methods.sql'),
    ('table', 'billing_purchases', '001initialpersistenceschema.sql'),
    ('table', 'event_idempotency_ledger', '001initialpersistenceschema.sql'),
    ('table', 'feed_ingest_log', '010_threat_feed_tables.sql'),
    ('table', 'history_events', '001initialpersistenceschema.sql'),
    ('table', 'incidents', '001initialpersistenceschema.sql'),
    ('table', 'install_key_issuance_history', '001initialpersistenceschema.sql'),
    ('table', 'install_key_records', '001initialpersistenceschema.sql'),
    ('table', 'ioc_records', '010_threat_feed_tables.sql'),
    ('table', 'ironclaw_agent_baselines', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_agent_observations', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_alerts', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_audit_logs', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_billing_purchases', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_drift_reports', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_event_idempotency', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_install_key_history', '004ironclawinternaltables.sql'),
    ('table', 'ironclaw_install_key_state', '004ironclawinternaltables.sql'),
    ('table', 'landing_counters', '011_landing_page_counters.sql'),
    ('table', 'legal_holds', '001initialpersistenceschema.sql'),
    ('table', 'orchestration_checkpoints', '002runtimestateschema.sql'),
    ('table', 'persistence_backends', '001initialpersistenceschema.sql'),
    ('table', 'persistence_failover_events', '001initialpersistenceschema.sql'),
    ('table', 'persistence_migrations', '001initialpersistenceschema.sql'),
    ('table', 'persistence_validation_runs', '001initialpersistenceschema.sql'),
    ('table', 'pipeline_runtime_states', '002runtimestateschema.sql'),
    ('table', 'policy_rules', '006_seed_ioc_patterns.sql'),
    ('table', 'policy_set_memberships', '007_seed_default_policy_set.sql'),
    ('table', 'policy_sets', '007_seed_default_policy_set.sql'),
    ('table', 'private', '004ironclawinternaltables.sql'),
    ('table', 'quarantine_events', '001initialpersistenceschema.sql'),
    ('table', 'quarantine_items', '001initialpersistenceschema.sql'),
    ('table', 'queue_runtime_leases', '002runtimestateschema.sql'),
    ('table', 'release_policy_decisions', '001initialpersistenceschema.sql'),
    ('table', 'restore_runs', '001initialpersistenceschema.sql'),
    ('table', 'retention_policies', '001initialpersistenceschema.sql'),
    ('table', 'retention_runs', '001initialpersistenceschema.sql'),
    ('table', 'review_queue_items', '001initialpersistenceschema.sql'),
    ('table', 'review_state_snapshots', '002runtimestateschema.sql'),
    ('table', 'runtime_blocks', '016_runtime_blocks.sql'),
    ('table', 'runtime_checkpoints', '001initialpersistenceschema.sql'),
    ('table', 'runtime_incidents', '002runtimestateschema.sql'),
    ('table', 'runtime_replay_runs', '002runtimestateschema.sql'),
    ('table', 'runtime_review_queue', '002runtimestateschema.sql'),
    ('table', 'runtime_session_events', '002runtimestateschema.sql'),
    ('table', 'runtime_sessions', '002runtimestateschema.sql'),
    ('table', 'runtime_state_checkpoints', '002runtimestateschema.sql'),
    ('table', 'runtime_state_snapshots', '002runtimestateschema.sql'),
    ('table', 'scan_patterns', '006_seed_ioc_patterns.sql'),
    ('table', 'stripe_checkout_fulfillments', '021_stripe_checkout_fulfillment.sql'),
    ('table', 'stripe_customer_links', '015_stripe_customer_links.sql'),
    ('table', 'stripe_payment_refund_markers', '021_stripe_checkout_fulfillment.sql'),
    ('table', 'stripe_webhook_events', '009_webhooks.sql'),
    ('table', 'supervisor_state_snapshots', '002runtimestateschema.sql'),
    ('table', 'telemetry_events', '001initialpersistenceschema.sql'),
    ('table', 'unit_ledger', '017_unit_wallets.sql'),
    ('table', 'unit_wallets', '017_unit_wallets.sql'),
    ('table', 'webhook_delivery_log', '009_webhooks.sql'),
    ('table', 'webhook_subscriptions', '009_webhooks.sql'),
    ('function', 'credit_unit_wallet_once', '019_atomic_unit_wallet_credits.sql'),
    ('function', 'get_install_key_commands', '014_install_key_saved_commands.sql'),
    ('function', 'get_landing_counters', '011_landing_page_counters.sql'),
    ('function', 'ioc_records_set_updated_at', '010_threat_feed_tables.sql'),
    ('function', 'ironclaw_set_updated_at', '004ironclawinternaltables.sql'),
    ('function', 'issue_install_key_claim', '012_install_key_handoffs.sql'),
    ('function', 'issue_install_key_record_with_secret', '012_install_key_handoffs.sql'),
    ('function', 'landing_counter_compute', '011_landing_page_counters.sql'),
    ('function', 'landing_counter_hash32', '011_landing_page_counters.sql'),
    ('function', 'landing_counter_mul32', '011_landing_page_counters.sql'),
    ('function', 'landing_counter_value', '011_landing_page_counters.sql'),
    ('function', 'landing_counters_enforce_monotonic', '011_landing_page_counters.sql'),
    ('function', 'mark_stripe_checkout_fulfillment', '021_stripe_checkout_fulfillment.sql'),
    ('function', 'prevent_webhook_append_only_mutation', '009_webhooks.sql'),
    ('function', 'record_stripe_payment_refund', '021_stripe_checkout_fulfillment.sql'),
    ('function', 'redeem_install_key_claim', '012_install_key_handoffs.sql'),
    ('function', 'register_stripe_checkout_fulfillment', '021_stripe_checkout_fulfillment.sql'),
    ('function', 'revoke_install_key_claims', '020_refund_revocation.sql'),
    ('function', 'set_updated_at', '001initialpersistenceschema.sql'),
    ('function', 'store_install_key_command', '014_install_key_saved_commands.sql'),
    ('function', 'store_install_key_secret', '012_install_key_handoffs.sql'),
    ('function', 'upgrade_landing_counter', '011_landing_page_counters.sql')
)
select
    e.kind,
    e.object_name,
    e.source,
    case e.kind
        when 'table' then
            exists (
                select 1
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where n.nspname = 'public'
                  and c.relname = e.object_name
                  and c.relkind in ('r', 'p')
            )
        else
            exists (
                select 1
                from pg_proc p
                join pg_namespace n on n.oid = p.pronamespace
                where n.nspname = 'public'
                  and p.proname = e.object_name
            )
    end as present
from expected e
order by
    present asc,
    e.source,
    e.kind,
    e.object_name;
