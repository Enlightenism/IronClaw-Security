from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from app.core.supabase_persistence import (
    PersistenceError,
    create_webhook_subscription,
    delete_rate_limit_state,
    delete_webhook_subscription,
    get_policy_set,
    get_rate_limit_state,
    get_scan_by_id,
    get_scan_patterns,
    get_webhook_delivery_log,
    get_webhook_delivery_record,
    get_webhook_subscription,
    list_scans,
    list_webhook_subscriptions,
    update_webhook_delivery,
    update_webhook_subscription,
    upsert_audit_event,
    upsert_rate_limit_state,
    upsert_scan,
    upsert_webhook_delivery,
)

# ---------------------------------------------------------------------------
# Patch target
# ---------------------------------------------------------------------------
_PATCH_TARGET = "app.core.supabase_persistence.get_supabase_service_client"


# ---------------------------------------------------------------------------
# Query-builder mock factory
# ---------------------------------------------------------------------------


def _make_qb(
    return_data: object = None,
    *,
    side_effect: BaseException | None = None,
) -> MagicMock:
    qb = MagicMock()
    for method in (
        "select",
        "eq",
        "in_",
        "order",
        "range",
        "maybe_single",
        "upsert",
        "insert",
        "update",
        "delete",
    ):
        getattr(qb, method).return_value = qb

    resp = MagicMock()
    resp.data = return_data

    if side_effect is not None:
        qb.execute.side_effect = side_effect
    else:
        qb.execute.return_value = resp

    return qb


def _make_client(
    return_data: object = None,
    *,
    side_effect: BaseException | None = None,
) -> MagicMock:
    qb = _make_qb(return_data, side_effect=side_effect)
    client = MagicMock()
    client.table.return_value = qb
    return client


# ---------------------------------------------------------------------------
# Multi-table client factory for get_policy_set
# ---------------------------------------------------------------------------


def _make_policy_client(
    *,
    set_data: object,
    membership_data: object,
    rules_data: object,
) -> MagicMock:
    set_qb = _make_qb(set_data)
    membership_qb = _make_qb(membership_data)
    rules_qb = _make_qb(rules_data)

    client = MagicMock()
    client.table.side_effect = [set_qb, membership_qb, rules_qb]
    return client


# ---------------------------------------------------------------------------
# Sample fixtures
# ---------------------------------------------------------------------------

_POLICY_SET_ROW: dict = {
    "id": "pset-001",
    "set_key": "default",
    "description": "Default policy set",
    "is_active": True,
    "created_at": "2026-06-01T00:00:00+00:00",
}

_MEMBERSHIP_ROWS: list[dict] = [
    {"policy_rule_id": "rule-001", "policy_set_id": "pset-001"},
    {"policy_rule_id": "rule-002", "policy_set_id": "pset-001"},
]

_RULE_ROWS: list[dict] = [
    {
        "id": "rule-001",
        "rule_key": "block_injection",
        "action": "block",
        "severity": "critical",
        "is_active": True,
    },
    {
        "id": "rule-002",
        "rule_key": "warn_exfiltration",
        "action": "warn",
        "severity": "high",
        "is_active": True,
    },
]

_SCAN_PATTERN_ROW: dict = {
    "id": "pat-001",
    "pattern_key": "sql_injection",
    "pattern_type": "regex",
    "pattern_value": r"(?i)(select|insert|drop)\s",
    "is_active": True,
    "created_at": "2026-06-01T00:00:00+00:00",
}

_RATE_LIMIT_ROW: dict = {
    "key": "agent:agent-001:scan",
    "count": 5,
    "window_start": "2026-06-07T11:00:00+00:00",
    "expires_at": "2026-06-07T12:00:00+00:00",
}

_RATE_LIMIT_STATE_ROW: dict = {
    "key": "ip:127.0.0.1",
    "count": 3,
    "window_start": 1780000000.0,
    "window_seconds": 60,
    "rate_limit": 60,
    "updated_at": "2026-06-08T00:00:00+00:00",
}

_SCAN_ROW: dict = {
    "scan_id": "scan-001",
    "agent_id": "agent-abc",
    "verdict": "block",
    "created_at": "2026-06-08T00:00:00+00:00",
}

_AUDIT_ROW: dict = {
    "event_id": "evt-001",
    "event_type": "scan.completed",
    "tenant_id": "tenant-001",
    "created_at": "2026-06-08T00:00:00+00:00",
}

_WEBHOOK_SUB_ROW: dict = {
    "id": "sub-001",
    "tenant_id": "tenant-001",
    "target_url": "https://example.com/hook",
    "active": True,
    "created_at": "2026-06-08T00:00:00+00:00",
}

_WEBHOOK_DELIVERY_ROW: dict = {
    "id": "del-001",
    "tenant_id": "tenant-001",
    "subscription_id": "sub-001",
    "event_type": "scan.completed",
    "status": "delivered",
    "created_at": "2026-06-08T00:00:00+00:00",
}


# ===========================================================================
# PersistenceError
# ===========================================================================


class TestPersistenceError:
    def test_operation_only_str_equals_operation(self):
        err = PersistenceError("upsert_scan")
        assert str(err) == "upsert_scan"

    def test_operation_attr_stored(self):
        err = PersistenceError("upsert_scan")
        assert err.operation == "upsert_scan"

    def test_operation_and_message_formatted(self):
        err = PersistenceError("upsert_scan", "conflict on scan_id")
        assert str(err) == "[upsert_scan] conflict on scan_id"

    def test_empty_message_uses_operation_only(self):
        err = PersistenceError("op", "")
        assert str(err) == "op"

    def test_cause_none_by_default(self):
        err = PersistenceError("op")
        assert err.cause is None

    def test_cause_stored_when_provided(self):
        original = ValueError("root")
        err = PersistenceError("op", "msg", cause=original)
        assert err.cause is original

    def test_is_runtime_error_subclass(self):
        assert isinstance(PersistenceError("op"), RuntimeError)


# ===========================================================================
# _wrap — PersistenceError raised and _logger.error called
# ===========================================================================


class TestWrap:
    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("db fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_scan({"scan_id": "s1", "verdict": "allow"})
        assert exc_info.value.operation == "upsert_scan"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_scan({"scan_id": "s1", "verdict": "allow"})
        assert exc_info.value.operation == "upsert_scan"

    def test_wrap_logs_via_logger_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("log this"))
        with patch(_PATCH_TARGET, return_value=client):
            with patch("app.core.supabase_persistence._logger") as mock_logger:
                with pytest.raises(PersistenceError):
                    upsert_scan({"scan_id": "s1"})
        mock_logger.error.assert_called_once()

    def test_wrap_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("original cause")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_scan({"scan_id": "s1"})
        assert exc_info.value.cause is original


# ===========================================================================
# get_policy_set
# ===========================================================================


class TestGetPolicySet:
    def test_returns_dict_with_policy_set_and_rules_keys(self):
        client = _make_policy_client(
            set_data=_POLICY_SET_ROW,
            membership_data=_MEMBERSHIP_ROWS,
            rules_data=_RULE_ROWS,
        )
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert result is not None
        assert "policy_set" in result
        assert "rules" in result

    def test_policy_set_value_matches_db_row(self):
        client = _make_policy_client(
            set_data=_POLICY_SET_ROW,
            membership_data=_MEMBERSHIP_ROWS,
            rules_data=_RULE_ROWS,
        )
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert result["policy_set"]["set_key"] == "default"
        assert result["policy_set"]["id"] == "pset-001"

    def test_rules_list_populated_from_policy_rules_table(self):
        client = _make_policy_client(
            set_data=_POLICY_SET_ROW,
            membership_data=_MEMBERSHIP_ROWS,
            rules_data=_RULE_ROWS,
        )
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert isinstance(result["rules"], list)
        assert len(result["rules"]) == 2
        rule_ids = {r["id"] for r in result["rules"]}
        assert rule_ids == {"rule-001", "rule-002"}

    def test_membership_rows_keyed_on_policy_rule_id_are_resolved(self):
        memberships = [
            {"policy_rule_id": "rule-001", "policy_set_id": "pset-001"},
        ]
        rules = [_RULE_ROWS[0]]
        client = _make_policy_client(
            set_data=_POLICY_SET_ROW,
            membership_data=memberships,
            rules_data=rules,
        )
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert result["rules"][0]["id"] == "rule-001"

    def test_membership_rows_missing_policy_rule_id_are_skipped(self):
        memberships = [
            {"rule_id": "rule-999", "policy_set_id": "pset-001"},
        ]
        client = _make_policy_client(
            set_data=_POLICY_SET_ROW,
            membership_data=memberships,
            rules_data=[],
        )
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert result["rules"] == []

    def test_policy_rules_table_queried_with_ids_from_policy_rule_id_column(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb(_MEMBERSHIP_ROWS)
        rules_qb = _make_qb(_RULE_ROWS)

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb, rules_qb]

        with patch(_PATCH_TARGET, return_value=client):
            get_policy_set("default")

        rules_qb.in_.assert_called_once_with("id", ["rule-001", "rule-002"])

    def test_membership_table_queried_with_policy_set_id(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb(_MEMBERSHIP_ROWS)
        rules_qb = _make_qb(_RULE_ROWS)

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb, rules_qb]

        with patch(_PATCH_TARGET, return_value=client):
            get_policy_set("default")

        membership_qb.eq.assert_called_once_with("policy_set_id", "pset-001")

    def test_policy_sets_table_queried_by_set_key(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb(_MEMBERSHIP_ROWS)
        rules_qb = _make_qb(_RULE_ROWS)

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb, rules_qb]

        with patch(_PATCH_TARGET, return_value=client):
            get_policy_set("default")

        set_qb.eq.assert_called_once_with("set_key", "default")

    def test_three_distinct_tables_queried_in_order(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb(_MEMBERSHIP_ROWS)
        rules_qb = _make_qb(_RULE_ROWS)

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb, rules_qb]

        with patch(_PATCH_TARGET, return_value=client):
            get_policy_set("default")

        assert client.table.call_count == 3
        assert client.table.call_args_list == [
            call("policy_sets"),
            call("policy_set_memberships"),
            call("policy_rules"),
        ]

    def test_policy_set_id_extracted_from_id_key(self):
        row = {**_POLICY_SET_ROW, "id": "pset-id-key"}
        set_qb = _make_qb(row)
        membership_qb = _make_qb([])
        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb]
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")
        membership_qb.eq.assert_called_once_with("policy_set_id", "pset-id-key")
        assert result is not None

    def test_policy_set_id_extracted_from_policy_set_id_key_when_id_absent(self):
        row = {k: v for k, v in _POLICY_SET_ROW.items() if k != "id"}
        row["policy_set_id"] = "pset-alt-key"
        set_qb = _make_qb(row)
        membership_qb = _make_qb([])
        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb]
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")
        membership_qb.eq.assert_called_once_with("policy_set_id", "pset-alt-key")
        assert result is not None

    def test_returns_none_when_set_not_found_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("nonexistent")

        assert result is None

    def test_returns_none_when_set_not_found_data_is_empty_dict(self):
        client = _make_client({})
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("nonexistent")

        assert result is None

    def test_returns_none_when_set_not_found_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("nonexistent")

        assert result is None

    def test_rules_empty_when_no_memberships(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb([])

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb]

        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert result["rules"] == []

    def test_rules_empty_when_membership_data_is_none(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb(None)

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb]

        with patch(_PATCH_TARGET, return_value=client):
            result = get_policy_set("default")

        assert result["rules"] == []

    def test_policy_rules_table_not_queried_when_no_rule_ids(self):
        set_qb = _make_qb(_POLICY_SET_ROW)
        membership_qb = _make_qb([])

        client = MagicMock()
        client.table.side_effect = [set_qb, membership_qb]

        with patch(_PATCH_TARGET, return_value=client):
            get_policy_set("default")

        assert client.table.call_count == 2

    def test_empty_set_key_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="set_key is required"):
            get_policy_set("")

    def test_whitespace_set_key_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="set_key is required"):
            get_policy_set("   ")

    def test_persistence_error_operation_is_get_policy_set(self):
        with pytest.raises(PersistenceError) as exc_info:
            get_policy_set("")
        assert exc_info.value.operation == "get_policy_set"

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("db error"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_policy_set("default")

        assert exc_info.value.operation == "get_policy_set"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_policy_set("default")

        assert exc_info.value.operation == "get_policy_set"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("connection lost")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_policy_set("default")

        assert exc_info.value.cause is original


# ===========================================================================
# get_scan_patterns
# ===========================================================================


class TestGetScanPatterns:
    def test_returns_list_of_patterns(self):
        client = _make_client([_SCAN_PATTERN_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_patterns()

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["pattern_key"] == "sql_injection"

    def test_default_is_active_true_filter_applied(self):
        qb = _make_qb([_SCAN_PATTERN_ROW])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns()

        qb.eq.assert_any_call("is_active", True)

    def test_scan_patterns_table_queried(self):
        qb = _make_qb([_SCAN_PATTERN_ROW])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns()

        client.table.assert_called_once_with("scan_patterns")

    def test_is_active_false_filter_applied_when_passed(self):
        qb = _make_qb([])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns(is_active=False)

        qb.eq.assert_any_call("is_active", False)

    def test_is_active_none_skips_is_active_filter(self):
        qb = _make_qb([_SCAN_PATTERN_ROW])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns(is_active=None)

        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("is_active", True) not in called_args
        assert ("is_active", False) not in called_args
        assert ("is_active", None) not in called_args

    def test_pattern_type_filter_applied_when_passed(self):
        qb = _make_qb([_SCAN_PATTERN_ROW])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns(pattern_type="regex")

        qb.eq.assert_any_call("pattern_type", "regex")

    def test_pattern_type_filter_not_applied_when_none(self):
        qb = _make_qb([_SCAN_PATTERN_ROW])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns(pattern_type=None)

        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "pattern_type" for a in called_args)

    def test_both_is_active_and_pattern_type_filters_applied(self):
        qb = _make_qb([_SCAN_PATTERN_ROW])
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_scan_patterns(is_active=True, pattern_type="keyword")

        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("is_active", True) in called_args
        assert ("pattern_type", "keyword") in called_args

    def test_empty_list_returned_when_no_patterns(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_patterns()

        assert result == []

    def test_none_data_returns_empty_list(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_patterns()

        assert result == []

    def test_single_dict_response_wrapped_in_list(self):
        client = _make_client(_SCAN_PATTERN_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_patterns()

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["pattern_key"] == "sql_injection"

    def test_multiple_patterns_returned(self):
        second = {**_SCAN_PATTERN_ROW, "id": "pat-002", "pattern_key": "xss_basic"}
        client = _make_client([_SCAN_PATTERN_ROW, second])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_patterns()

        assert len(result) == 2

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("read failed"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_scan_patterns()

        assert exc_info.value.operation == "get_scan_patterns"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("conn reset"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_scan_patterns()

        assert exc_info.value.operation == "get_scan_patterns"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("disk full")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_scan_patterns()

        assert exc_info.value.cause is original


# ===========================================================================
# get_rate_limit_state
# ===========================================================================


class TestGetRateLimitState:
    def test_returns_dict_when_row_found(self):
        client = _make_client(_RATE_LIMIT_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_rate_limit_state("agent:agent-001:scan")

        assert result is not None
        assert isinstance(result, dict)
        assert result["key"] == "agent:agent-001:scan"
        assert result["count"] == 5

    def test_returns_dict_when_data_is_single_element_list(self):
        client = _make_client([_RATE_LIMIT_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_rate_limit_state("agent:agent-001:scan")

        assert result is not None
        assert result["key"] == "agent:agent-001:scan"

    def test_rate_limit_state_table_queried(self):
        qb = _make_qb(_RATE_LIMIT_ROW)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_rate_limit_state("agent:agent-001:scan")

        client.table.assert_called_once_with("rate_limit_state")

    def test_query_filters_by_key(self):
        qb = _make_qb(_RATE_LIMIT_ROW)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_rate_limit_state("agent:agent-001:scan")

        qb.eq.assert_called_once_with("key", "agent:agent-001:scan")

    def test_key_is_stripped_before_query(self):
        qb = _make_qb(_RATE_LIMIT_ROW)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            get_rate_limit_state("  agent:agent-001:scan  ")

        qb.eq.assert_called_once_with("key", "agent:agent-001:scan")

    def test_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_rate_limit_state("agent:missing:scan")

        assert result is None

    def test_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_rate_limit_state("agent:missing:scan")

        assert result is None

    def test_returns_none_when_data_is_empty_dict(self):
        client = _make_client({})
        with patch(_PATCH_TARGET, return_value=client):
            result = get_rate_limit_state("agent:missing:scan")

        assert result is None

    def test_empty_key_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="key is required"):
            get_rate_limit_state("")

    def test_whitespace_key_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="key is required"):
            get_rate_limit_state("   ")

    def test_persistence_error_operation_is_get_rate_limit_state(self):
        with pytest.raises(PersistenceError) as exc_info:
            get_rate_limit_state("")
        assert exc_info.value.operation == "get_rate_limit_state"

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("db error"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.operation == "get_rate_limit_state"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.operation == "get_rate_limit_state"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("connection refused")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.cause is original


# ===========================================================================
# upsert_rate_limit_state
# ===========================================================================


class TestUpsertRateLimitState:
    def test_success_returns_upserted_row(self):
        client = _make_client([_RATE_LIMIT_STATE_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        assert result["key"] == "ip:127.0.0.1"
        assert result["count"] == 3

    def test_returns_dict_response_directly(self):
        client = _make_client(_RATE_LIMIT_STATE_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        assert result["key"] == "ip:127.0.0.1"

    def test_returns_input_record_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        assert result is _RATE_LIMIT_STATE_ROW

    def test_missing_key_raises_persistence_error(self):
        record = {k: v for k, v in _RATE_LIMIT_STATE_ROW.items() if k != "key"}
        with pytest.raises(PersistenceError, match="key"):
            upsert_rate_limit_state(record)

    def test_persistence_error_operation_is_upsert_rate_limit_state(self):
        record = {k: v for k, v in _RATE_LIMIT_STATE_ROW.items() if k != "key"}
        with pytest.raises(PersistenceError) as exc_info:
            upsert_rate_limit_state(record)
        assert exc_info.value.operation == "upsert_rate_limit_state"

    def test_updated_at_injected_when_absent(self):
        record = {k: v for k, v in _RATE_LIMIT_STATE_ROW.items() if k != "updated_at"}
        qb = _make_qb([_RATE_LIMIT_STATE_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_rate_limit_state(record)
        passed_record = qb.upsert.call_args.args[0]
        assert "updated_at" in passed_record

    def test_updated_at_not_overwritten_when_present(self):
        qb = _make_qb([_RATE_LIMIT_STATE_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        passed_record = qb.upsert.call_args.args[0]
        assert passed_record["updated_at"] == "2026-06-08T00:00:00+00:00"

    def test_rate_limit_state_table_queried(self):
        qb = _make_qb([_RATE_LIMIT_STATE_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        client.table.assert_called_once_with("rate_limit_state")

    def test_upsert_conflicts_on_key(self):
        qb = _make_qb([_RATE_LIMIT_STATE_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        call_kwargs = qb.upsert.call_args
        assert call_kwargs.kwargs.get("on_conflict") == "key"

    def test_supabase_api_error_wrapped_as_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("write failed"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        assert exc_info.value.operation == "upsert_rate_limit_state"

    def test_supabase_client_error_wrapped_as_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        assert exc_info.value.operation == "upsert_rate_limit_state"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("conflict")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_rate_limit_state(_RATE_LIMIT_STATE_ROW)
        assert exc_info.value.cause is original


# ===========================================================================
# delete_rate_limit_state
# ===========================================================================


class TestDeleteRateLimitState:
    def test_success_returns_none(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            result = delete_rate_limit_state("agent:agent-001:scan")

        assert result is None

    def test_rate_limit_state_table_queried(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            delete_rate_limit_state("agent:agent-001:scan")

        client.table.assert_called_once_with("rate_limit_state")

    def test_delete_called_on_query_builder(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            delete_rate_limit_state("agent:agent-001:scan")

        qb.delete.assert_called_once()

    def test_delete_filtered_by_key(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            delete_rate_limit_state("agent:agent-001:scan")

        qb.eq.assert_called_once_with("key", "agent:agent-001:scan")

    def test_key_is_stripped_before_delete(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            delete_rate_limit_state("  agent:agent-001:scan  ")

        qb.eq.assert_called_once_with("key", "agent:agent-001:scan")

    def test_execute_is_called(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            delete_rate_limit_state("agent:agent-001:scan")

        qb.execute.assert_called_once()

    def test_empty_key_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="key is required"):
            delete_rate_limit_state("")

    def test_whitespace_key_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="key is required"):
            delete_rate_limit_state("   ")

    def test_persistence_error_operation_is_delete_rate_limit_state(self):
        with pytest.raises(PersistenceError) as exc_info:
            delete_rate_limit_state("")
        assert exc_info.value.operation == "delete_rate_limit_state"

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("delete failed"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.operation == "delete_rate_limit_state"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("conn refused"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.operation == "delete_rate_limit_state"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        original = SupabaseClientError("disk full")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.cause is original

    def test_persistence_error_wraps_cause_api_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("network timeout")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_rate_limit_state("agent:agent-001:scan")

        assert exc_info.value.cause is original


# ===========================================================================
# upsert_scan
# ===========================================================================


class TestUpsertScan:
    def test_returns_first_element_of_list_response(self):
        client = _make_client([_SCAN_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_scan(_SCAN_ROW)
        assert result["scan_id"] == "scan-001"

    def test_returns_dict_response_directly(self):
        client = _make_client(_SCAN_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_scan(_SCAN_ROW)
        assert result["scan_id"] == "scan-001"

    def test_returns_input_record_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_scan(_SCAN_ROW)
        assert result is _SCAN_ROW

    def test_scan_history_table_queried(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_scan(_SCAN_ROW)
        client.table.assert_called_once_with("scan_history")

    def test_upsert_called_on_query_builder(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_scan(_SCAN_ROW)
        qb.upsert.assert_called_once()

    def test_upsert_conflicts_on_scan_id(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_scan(_SCAN_ROW)
        call_kwargs = qb.upsert.call_args
        assert call_kwargs.kwargs.get("on_conflict") == "scan_id"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_scan(_SCAN_ROW)
        assert exc_info.value.operation == "upsert_scan"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_scan(_SCAN_ROW)
        assert exc_info.value.operation == "upsert_scan"


# ===========================================================================
# get_scan_by_id
# ===========================================================================


class TestGetScanById:
    def test_returns_dict_when_row_found(self):
        client = _make_client(_SCAN_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_by_id("scan-001")
        assert result["scan_id"] == "scan-001"

    def test_returns_first_element_when_data_is_list(self):
        client = _make_client([_SCAN_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_by_id("scan-001")
        assert result is not None
        assert result["scan_id"] == "scan-001"

    def test_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_by_id("missing")
        assert result is None

    def test_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_scan_by_id("missing")
        assert result is None

    def test_scan_history_table_queried(self):
        qb = _make_qb(_SCAN_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_scan_by_id("scan-001")
        client.table.assert_called_once_with("scan_history")

    def test_query_filters_by_scan_id(self):
        qb = _make_qb(_SCAN_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_scan_by_id("scan-001")
        qb.eq.assert_called_once_with("scan_id", "scan-001")

    def test_maybe_single_called(self):
        qb = _make_qb(_SCAN_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_scan_by_id("scan-001")
        qb.maybe_single.assert_called_once()

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_scan_by_id("scan-001")
        assert exc_info.value.operation == "get_scan_by_id"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_scan_by_id("scan-001")
        assert exc_info.value.operation == "get_scan_by_id"


# ===========================================================================
# list_scans
# ===========================================================================


class TestListScans:
    def test_returns_list_of_scan_rows(self):
        client = _make_client([_SCAN_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = list_scans()
        assert isinstance(result, list)
        assert result[0]["scan_id"] == "scan-001"

    def test_returns_empty_list_when_no_data(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = list_scans()
        assert result == []

    def test_returns_empty_list_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_scans()
        assert result == []

    def test_single_dict_response_wrapped_in_list(self):
        client = _make_client(_SCAN_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_scans()
        assert isinstance(result, list)
        assert result[0]["scan_id"] == "scan-001"

    def test_scan_history_table_queried(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans()
        client.table.assert_called_once_with("scan_history")

    def test_agent_id_filter_applied_when_passed(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans(agent_id="agent-abc")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("agent_id", "agent-abc") in called_args

    def test_agent_id_filter_not_applied_when_none(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans(agent_id=None)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "agent_id" for a in called_args)

    def test_verdict_filter_applied_when_passed(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans(verdict="block")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("verdict", "block") in called_args

    def test_verdict_filter_not_applied_when_none(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans(verdict=None)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "verdict" for a in called_args)

    def test_order_by_created_at_desc(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans()
        qb.order.assert_called_once_with("created_at", desc=True)

    def test_range_applied_with_default_limit_and_offset(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans()
        qb.range.assert_called_once_with(0, 99)

    def test_range_applied_with_custom_limit_and_offset(self):
        qb = _make_qb([_SCAN_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_scans(limit=10, offset=20)
        qb.range.assert_called_once_with(20, 29)

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_scans()
        assert exc_info.value.operation == "list_scans"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_scans()
        assert exc_info.value.operation == "list_scans"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("db gone")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_scans()
        assert exc_info.value.cause is original


# ===========================================================================
# upsert_audit_event
# ===========================================================================


class TestUpsertAuditEvent:
    def test_returns_first_element_of_list_response(self):
        client = _make_client([_AUDIT_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_audit_event(_AUDIT_ROW)
        assert result["event_id"] == "evt-001"

    def test_returns_dict_response_directly(self):
        client = _make_client(_AUDIT_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_audit_event(_AUDIT_ROW)
        assert result["event_id"] == "evt-001"

    def test_returns_input_record_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_audit_event(_AUDIT_ROW)
        assert result is _AUDIT_ROW

    def test_audit_events_table_queried(self):
        qb = _make_qb([_AUDIT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_audit_event(_AUDIT_ROW)
        client.table.assert_called_once_with("audit_events")

    def test_upsert_used_when_event_id_present(self):
        qb = _make_qb([_AUDIT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_audit_event(_AUDIT_ROW)
        qb.upsert.assert_called_once()
        qb.insert.assert_not_called()

    def test_insert_used_when_event_id_absent(self):
        record = {k: v for k, v in _AUDIT_ROW.items() if k != "event_id"}
        qb = _make_qb([record])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_audit_event(record)
        qb.insert.assert_called_once()
        qb.upsert.assert_not_called()

    def test_upsert_conflicts_on_event_id(self):
        qb = _make_qb([_AUDIT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_audit_event(_AUDIT_ROW)
        call_kwargs = qb.upsert.call_args
        assert call_kwargs.kwargs.get("on_conflict") == "event_id"

    def test_created_at_injected_when_absent(self):
        record = {k: v for k, v in _AUDIT_ROW.items() if k != "created_at"}
        qb = _make_qb([_AUDIT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_audit_event(record)
        passed_record = qb.upsert.call_args.args[0]
        assert "created_at" in passed_record

    def test_created_at_not_overwritten_when_present(self):
        qb = _make_qb([_AUDIT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_audit_event(_AUDIT_ROW)
        passed_record = qb.upsert.call_args.args[0]
        assert passed_record["created_at"] == "2026-06-08T00:00:00+00:00"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_audit_event(_AUDIT_ROW)
        assert exc_info.value.operation == "upsert_audit_event"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_audit_event(_AUDIT_ROW)
        assert exc_info.value.operation == "upsert_audit_event"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("conflict")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_audit_event(_AUDIT_ROW)
        assert exc_info.value.cause is original


# ===========================================================================
# create_webhook_subscription
# ===========================================================================


class TestCreateWebhookSubscription:
    def test_returns_first_element_of_list_response(self):
        client = _make_client([_WEBHOOK_SUB_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = create_webhook_subscription(_WEBHOOK_SUB_ROW)
        assert result["id"] == "sub-001"

    def test_returns_dict_response_directly(self):
        client = _make_client(_WEBHOOK_SUB_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = create_webhook_subscription(_WEBHOOK_SUB_ROW)
        assert result["id"] == "sub-001"

    def test_returns_input_record_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = create_webhook_subscription(_WEBHOOK_SUB_ROW)
        assert result is _WEBHOOK_SUB_ROW

    def test_webhook_subscriptions_table_queried(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            create_webhook_subscription(_WEBHOOK_SUB_ROW)
        client.table.assert_called_once_with("webhook_subscriptions")

    def test_insert_called_on_query_builder(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            create_webhook_subscription(_WEBHOOK_SUB_ROW)
        qb.insert.assert_called_once()

    def test_created_at_injected_when_absent(self):
        record = {k: v for k, v in _WEBHOOK_SUB_ROW.items() if k != "created_at"}
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            create_webhook_subscription(record)
        passed_record = qb.insert.call_args.args[0]
        assert "created_at" in passed_record

    def test_created_at_not_overwritten_when_present(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            create_webhook_subscription(_WEBHOOK_SUB_ROW)
        passed_record = qb.insert.call_args.args[0]
        assert passed_record["created_at"] == "2026-06-08T00:00:00+00:00"

    def test_missing_tenant_id_raises_persistence_error(self):
        record = {k: v for k, v in _WEBHOOK_SUB_ROW.items() if k != "tenant_id"}
        with pytest.raises(PersistenceError, match="tenant_id"):
            create_webhook_subscription(record)

    def test_missing_target_url_raises_persistence_error(self):
        record = {k: v for k, v in _WEBHOOK_SUB_ROW.items() if k != "target_url"}
        with pytest.raises(PersistenceError, match="target_url"):
            create_webhook_subscription(record)

    def test_persistence_error_operation_is_create_webhook_subscription(self):
        record = {k: v for k, v in _WEBHOOK_SUB_ROW.items() if k != "tenant_id"}
        with pytest.raises(PersistenceError) as exc_info:
            create_webhook_subscription(record)
        assert exc_info.value.operation == "create_webhook_subscription"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                create_webhook_subscription(_WEBHOOK_SUB_ROW)
        assert exc_info.value.operation == "create_webhook_subscription"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                create_webhook_subscription(_WEBHOOK_SUB_ROW)
        assert exc_info.value.operation == "create_webhook_subscription"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("duplicate key")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                create_webhook_subscription(_WEBHOOK_SUB_ROW)
        assert exc_info.value.cause is original


# ===========================================================================
# list_webhook_subscriptions
# ===========================================================================


class TestListWebhookSubscriptions:
    def test_returns_list_of_subscription_rows(self):
        client = _make_client([_WEBHOOK_SUB_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = list_webhook_subscriptions("tenant-001")
        assert isinstance(result, list)
        assert result[0]["id"] == "sub-001"

    def test_returns_empty_list_when_no_data(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = list_webhook_subscriptions("tenant-001")
        assert result == []

    def test_returns_empty_list_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_webhook_subscriptions("tenant-001")
        assert result == []

    def test_single_dict_response_wrapped_in_list(self):
        client = _make_client(_WEBHOOK_SUB_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_webhook_subscriptions("tenant-001")
        assert isinstance(result, list)
        assert result[0]["id"] == "sub-001"

    def test_webhook_subscriptions_table_queried(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001")
        client.table.assert_called_once_with("webhook_subscriptions")

    def test_tenant_id_filter_applied(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("tenant_id", "tenant-001") in called_args

    def test_active_only_filter_applied_when_true(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001", active_only=True)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("active", True) in called_args

    def test_active_only_filter_not_applied_when_false(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001", active_only=False)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "active" for a in called_args)

    def test_order_by_created_at_desc(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001")
        qb.order.assert_called_once_with("created_at", desc=True)

    def test_range_applied_with_default_limit_and_offset(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001")
        qb.range.assert_called_once_with(0, 99)

    def test_range_applied_with_custom_limit_and_offset(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_webhook_subscriptions("tenant-001", limit=5, offset=10)
        qb.range.assert_called_once_with(10, 14)

    def test_empty_tenant_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="tenant_id"):
            list_webhook_subscriptions("")

    def test_persistence_error_operation_is_list_webhook_subscriptions(self):
        with pytest.raises(PersistenceError) as exc_info:
            list_webhook_subscriptions("")
        assert exc_info.value.operation == "list_webhook_subscriptions"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_webhook_subscriptions("tenant-001")
        assert exc_info.value.operation == "list_webhook_subscriptions"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_webhook_subscriptions("tenant-001")
        assert exc_info.value.operation == "list_webhook_subscriptions"


# ===========================================================================
# get_webhook_subscription
# ===========================================================================


class TestGetWebhookSubscription:
    def test_returns_dict_when_found(self):
        client = _make_client(_WEBHOOK_SUB_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_subscription("sub-001", "tenant-001")
        assert result["id"] == "sub-001"

    def test_returns_first_element_when_data_is_list(self):
        client = _make_client([_WEBHOOK_SUB_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_subscription("sub-001", "tenant-001")
        assert result is not None
        assert result["id"] == "sub-001"

    def test_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_subscription("sub-missing", "tenant-001")
        assert result is None

    def test_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_subscription("sub-missing", "tenant-001")
        assert result is None

    def test_webhook_subscriptions_table_queried(self):
        qb = _make_qb(_WEBHOOK_SUB_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_subscription("sub-001", "tenant-001")
        client.table.assert_called_once_with("webhook_subscriptions")

    def test_query_filters_by_id_and_tenant_id(self):
        qb = _make_qb(_WEBHOOK_SUB_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_subscription("sub-001", "tenant-001")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("id", "sub-001") in called_args
        assert ("tenant_id", "tenant-001") in called_args

    def test_maybe_single_called(self):
        qb = _make_qb(_WEBHOOK_SUB_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_subscription("sub-001", "tenant-001")
        qb.maybe_single.assert_called_once()

    def test_empty_subscription_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="subscription_id"):
            get_webhook_subscription("", "tenant-001")

    def test_empty_tenant_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="tenant_id"):
            get_webhook_subscription("sub-001", "")

    def test_persistence_error_operation_is_get_webhook_subscription(self):
        with pytest.raises(PersistenceError) as exc_info:
            get_webhook_subscription("", "tenant-001")
        assert exc_info.value.operation == "get_webhook_subscription"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_subscription("sub-001", "tenant-001")
        assert exc_info.value.operation == "get_webhook_subscription"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_subscription("sub-001", "tenant-001")
        assert exc_info.value.operation == "get_webhook_subscription"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("gone")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_subscription("sub-001", "tenant-001")
        assert exc_info.value.cause is original


# ===========================================================================
# update_webhook_subscription
# ===========================================================================


class TestUpdateWebhookSubscription:
    def test_returns_first_element_of_list_response(self):
        updated = {**_WEBHOOK_SUB_ROW, "active": False}
        client = _make_client([updated])
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert result["active"] is False

    def test_returns_dict_response_directly(self):
        updated = {**_WEBHOOK_SUB_ROW, "active": False}
        client = _make_client(updated)
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert result["active"] is False

    def test_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert result is None

    def test_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert result is None

    def test_webhook_subscriptions_table_queried(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        client.table.assert_called_once_with("webhook_subscriptions")

    def test_update_called_on_query_builder(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        qb.update.assert_called_once()

    def test_filters_by_id_and_tenant_id(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("id", "sub-001") in called_args
        assert ("tenant_id", "tenant-001") in called_args

    def test_updated_at_injected_into_updates(self):
        qb = _make_qb([_WEBHOOK_SUB_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        passed_updates = qb.update.call_args.args[0]
        assert "updated_at" in passed_updates

    def test_empty_subscription_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="subscription_id"):
            update_webhook_subscription("", "tenant-001", {})

    def test_empty_tenant_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="tenant_id"):
            update_webhook_subscription("sub-001", "", {})

    def test_persistence_error_operation_is_update_webhook_subscription(self):
        with pytest.raises(PersistenceError) as exc_info:
            update_webhook_subscription("", "tenant-001", {})
        assert exc_info.value.operation == "update_webhook_subscription"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert exc_info.value.operation == "update_webhook_subscription"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert exc_info.value.operation == "update_webhook_subscription"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("conflict")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                update_webhook_subscription("sub-001", "tenant-001", {"active": False})
        assert exc_info.value.cause is original


# ===========================================================================
# delete_webhook_subscription
# ===========================================================================


class TestDeleteWebhookSubscription:
    def test_success_returns_none(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            result = delete_webhook_subscription("sub-001", "tenant-001")
        assert result is None

    def test_webhook_subscriptions_table_queried(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            delete_webhook_subscription("sub-001", "tenant-001")
        client.table.assert_called_once_with("webhook_subscriptions")

    def test_delete_called_on_query_builder(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            delete_webhook_subscription("sub-001", "tenant-001")
        qb.delete.assert_called_once()

    def test_filters_by_id_and_tenant_id(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            delete_webhook_subscription("sub-001", "tenant-001")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("id", "sub-001") in called_args
        assert ("tenant_id", "tenant-001") in called_args

    def test_execute_is_called(self):
        qb = _make_qb(None)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            delete_webhook_subscription("sub-001", "tenant-001")
        qb.execute.assert_called_once()

    def test_empty_subscription_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="subscription_id"):
            delete_webhook_subscription("", "tenant-001")

    def test_empty_tenant_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="tenant_id"):
            delete_webhook_subscription("sub-001", "")

    def test_persistence_error_operation_is_delete_webhook_subscription(self):
        with pytest.raises(PersistenceError) as exc_info:
            delete_webhook_subscription("", "tenant-001")
        assert exc_info.value.operation == "delete_webhook_subscription"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_webhook_subscription("sub-001", "tenant-001")
        assert exc_info.value.operation == "delete_webhook_subscription"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_webhook_subscription("sub-001", "tenant-001")
        assert exc_info.value.operation == "delete_webhook_subscription"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("gone")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                delete_webhook_subscription("sub-001", "tenant-001")
        assert exc_info.value.cause is original


# ===========================================================================
# upsert_webhook_delivery
# ===========================================================================


class TestUpsertWebhookDelivery:
    def test_returns_first_element_of_list_response(self):
        client = _make_client([_WEBHOOK_DELIVERY_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        assert result["id"] == "del-001"

    def test_returns_dict_response_directly(self):
        client = _make_client(_WEBHOOK_DELIVERY_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        assert result["id"] == "del-001"

    def test_returns_input_record_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        assert result is _WEBHOOK_DELIVERY_ROW

    def test_webhook_deliveries_table_queried(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        client.table.assert_called_once_with("webhook_deliveries")

    def test_upsert_called_on_query_builder(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        qb.upsert.assert_called_once()

    def test_upsert_conflicts_on_id(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        call_kwargs = qb.upsert.call_args
        assert call_kwargs.kwargs.get("on_conflict") == "id"

    def test_created_at_injected_when_absent(self):
        record = {k: v for k, v in _WEBHOOK_DELIVERY_ROW.items() if k != "created_at"}
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_webhook_delivery(record)
        passed_record = qb.upsert.call_args.args[0]
        assert "created_at" in passed_record

    def test_created_at_not_overwritten_when_present(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        passed_record = qb.upsert.call_args.args[0]
        assert passed_record["created_at"] == "2026-06-08T00:00:00+00:00"

    def test_missing_id_raises_persistence_error(self):
        record = {k: v for k, v in _WEBHOOK_DELIVERY_ROW.items() if k != "id"}
        with pytest.raises(PersistenceError, match="id"):
            upsert_webhook_delivery(record)

    def test_missing_tenant_id_raises_persistence_error(self):
        record = {k: v for k, v in _WEBHOOK_DELIVERY_ROW.items() if k != "tenant_id"}
        with pytest.raises(PersistenceError, match="tenant_id"):
            upsert_webhook_delivery(record)

    def test_persistence_error_operation_is_upsert_webhook_delivery(self):
        record = {k: v for k, v in _WEBHOOK_DELIVERY_ROW.items() if k != "id"}
        with pytest.raises(PersistenceError) as exc_info:
            upsert_webhook_delivery(record)
        assert exc_info.value.operation == "upsert_webhook_delivery"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        assert exc_info.value.operation == "upsert_webhook_delivery"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        assert exc_info.value.operation == "upsert_webhook_delivery"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("conflict")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_webhook_delivery(_WEBHOOK_DELIVERY_ROW)
        assert exc_info.value.cause is original


# ===========================================================================
# update_webhook_delivery
# ===========================================================================


class TestUpdateWebhookDelivery:
    def test_returns_first_element_of_list_response(self):
        updated = {**_WEBHOOK_DELIVERY_ROW, "status": "failed"}
        client = _make_client([updated])
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_delivery("del-001", {"status": "failed"})
        assert result["status"] == "failed"

    def test_returns_dict_response_directly(self):
        updated = {**_WEBHOOK_DELIVERY_ROW, "status": "failed"}
        client = _make_client(updated)
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_delivery("del-001", {"status": "failed"})
        assert result["status"] == "failed"

    def test_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_delivery("del-001", {"status": "failed"})
        assert result is None

    def test_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = update_webhook_delivery("del-001", {"status": "failed"})
        assert result is None

    def test_webhook_deliveries_table_queried(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_delivery("del-001", {"status": "failed"})
        client.table.assert_called_once_with("webhook_deliveries")

    def test_update_called_on_query_builder(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_delivery("del-001", {"status": "failed"})
        qb.update.assert_called_once()

    def test_filters_by_delivery_id(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            update_webhook_delivery("del-001", {"status": "failed"})
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("id", "del-001") in called_args

    def test_empty_delivery_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="delivery_id"):
            update_webhook_delivery("", {"status": "failed"})

    def test_persistence_error_operation_is_update_webhook_delivery(self):
        with pytest.raises(PersistenceError) as exc_info:
            update_webhook_delivery("", {"status": "failed"})
        assert exc_info.value.operation == "update_webhook_delivery"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                update_webhook_delivery("del-001", {"status": "failed"})
        assert exc_info.value.operation == "update_webhook_delivery"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                update_webhook_delivery("del-001", {"status": "failed"})
        assert exc_info.value.operation == "update_webhook_delivery"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("gone")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                update_webhook_delivery("del-001", {"status": "failed"})
        assert exc_info.value.cause is original


# ===========================================================================
# get_webhook_delivery_record
# ===========================================================================


class TestGetWebhookDeliveryRecord:
    def test_returns_dict_when_found(self):
        client = _make_client(_WEBHOOK_DELIVERY_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_record("del-001")
        assert result["id"] == "del-001"

    def test_returns_first_element_when_data_is_list(self):
        client = _make_client([_WEBHOOK_DELIVERY_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_record("del-001")
        assert result is not None
        assert result["id"] == "del-001"

    def test_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_record("del-missing")
        assert result is None

    def test_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_record("del-missing")
        assert result is None

    def test_webhook_deliveries_table_queried(self):
        qb = _make_qb(_WEBHOOK_DELIVERY_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_record("del-001")
        client.table.assert_called_once_with("webhook_deliveries")

    def test_query_filters_by_id(self):
        qb = _make_qb(_WEBHOOK_DELIVERY_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_record("del-001")
        qb.eq.assert_called_once_with("id", "del-001")

    def test_maybe_single_called(self):
        qb = _make_qb(_WEBHOOK_DELIVERY_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_record("del-001")
        qb.maybe_single.assert_called_once()

    def test_empty_delivery_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="delivery_id"):
            get_webhook_delivery_record("")

    def test_persistence_error_operation_is_get_webhook_delivery_record(self):
        with pytest.raises(PersistenceError) as exc_info:
            get_webhook_delivery_record("")
        assert exc_info.value.operation == "get_webhook_delivery_record"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_delivery_record("del-001")
        assert exc_info.value.operation == "get_webhook_delivery_record"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_delivery_record("del-001")
        assert exc_info.value.operation == "get_webhook_delivery_record"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("gone")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_delivery_record("del-001")
        assert exc_info.value.cause is original


# ===========================================================================
# get_webhook_delivery_log
# ===========================================================================


class TestGetWebhookDeliveryLog:
    def test_returns_list_of_delivery_rows(self):
        client = _make_client([_WEBHOOK_DELIVERY_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_log("tenant-001")
        assert isinstance(result, list)
        assert result[0]["id"] == "del-001"

    def test_returns_empty_list_when_no_data(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_log("tenant-001")
        assert result == []

    def test_returns_empty_list_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_log("tenant-001")
        assert result == []

    def test_single_dict_response_wrapped_in_list(self):
        client = _make_client(_WEBHOOK_DELIVERY_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_webhook_delivery_log("tenant-001")
        assert isinstance(result, list)
        assert result[0]["id"] == "del-001"

    def test_webhook_deliveries_table_queried(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001")
        client.table.assert_called_once_with("webhook_deliveries")

    def test_tenant_id_filter_applied(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("tenant_id", "tenant-001") in called_args

    def test_subscription_id_filter_applied_when_passed(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", subscription_id="sub-001")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("subscription_id", "sub-001") in called_args

    def test_subscription_id_filter_not_applied_when_none(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", subscription_id=None)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "subscription_id" for a in called_args)

    def test_event_type_filter_applied_when_passed(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", event_type="scan.completed")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("event_type", "scan.completed") in called_args

    def test_event_type_filter_not_applied_when_none(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", event_type=None)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "event_type" for a in called_args)

    def test_delivery_status_filter_applied_when_passed(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", delivery_status="delivered")
        called_args = [c.args for c in qb.eq.call_args_list]
        assert ("status", "delivered") in called_args

    def test_delivery_status_filter_not_applied_when_none(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", delivery_status=None)
        called_args = [c.args for c in qb.eq.call_args_list]
        assert all(a[0] != "status" for a in called_args)

    def test_order_by_created_at_desc(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001")
        qb.order.assert_called_once_with("created_at", desc=True)

    def test_range_applied_with_default_limit_and_offset(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001")
        qb.range.assert_called_once_with(0, 99)

    def test_range_applied_with_custom_limit_and_offset(self):
        qb = _make_qb([_WEBHOOK_DELIVERY_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_webhook_delivery_log("tenant-001", limit=25, offset=50)
        qb.range.assert_called_once_with(50, 74)

    def test_empty_tenant_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="tenant_id"):
            get_webhook_delivery_log("")

    def test_persistence_error_operation_is_get_webhook_delivery_log(self):
        with pytest.raises(PersistenceError) as exc_info:
            get_webhook_delivery_log("")
        assert exc_info.value.operation == "get_webhook_delivery_log"

    def test_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("fail"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_delivery_log("tenant-001")
        assert exc_info.value.operation == "get_webhook_delivery_log"

    def test_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_delivery_log("tenant-001")
        assert exc_info.value.operation == "get_webhook_delivery_log"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("db gone")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_webhook_delivery_log("tenant-001")
        assert exc_info.value.cause is original
