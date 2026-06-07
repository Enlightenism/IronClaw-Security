from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from app.core.supabase_persistence import (
    PersistenceError,
    delete_rate_limit_state,
    get_policy_set,
    get_rate_limit_state,
    get_scan_patterns,
)

# ---------------------------------------------------------------------------
# Patch target — canonical module-level import; never patch supabaseclient
# directly. All tests in this file mock at the consumption site.
# ---------------------------------------------------------------------------
_PATCH_TARGET = "app.core.supabase_persistence.get_supabase_service_client"


# ---------------------------------------------------------------------------
# Query-builder mock factory — mirrors test_supabase_persistence_trust.py
# so the entire test/core suite uses one consistent mock shape.
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
# Multi-table client factory for get_policy_set which calls .table() three
# times in sequence: policy_sets → policy_set_memberships → policy_rules.
# ---------------------------------------------------------------------------


def _make_policy_client(
    *,
    set_data: object,
    membership_data: object,
    rules_data: object,
) -> MagicMock:
    """Return a client where each successive .table() call gets its own qb."""
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


# ===========================================================================
# get_policy_set
# ===========================================================================


class TestGetPolicySet:

    # -----------------------------------------------------------------------
    # Happy path — set found with rules via policy_rule_id column
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # policy_rule_id column normalization — membership rows carry
    # "policy_rule_id", NOT "rule_id". The function must extract
    # policy_rule_id correctly and never fall back to a missing "rule_id" key.
    # -----------------------------------------------------------------------

    def test_membership_rows_keyed_on_policy_rule_id_are_resolved(self):
        """Memberships use policy_rule_id; rules must still be fetched."""
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
        """Rows without policy_rule_id must not surface as rule IDs."""
        memberships = [
            {"rule_id": "rule-999", "policy_set_id": "pset-001"},  # wrong column name
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
        """Verifies in_() is called with IDs extracted via policy_rule_id."""
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

    # -----------------------------------------------------------------------
    # Not-found cases
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Empty memberships — no rules fetched
    # -----------------------------------------------------------------------

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

        # Only 2 table calls — policy_sets + policy_set_memberships
        assert client.table.call_count == 2

    # -----------------------------------------------------------------------
    # Validation guards
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # PersistenceError wrapping
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Default behaviour — is_active=True filter applied
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # is_active filter variants
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # pattern_type filter
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Response normalization
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # PersistenceError wrapping
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Happy path — row found
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Not-found — returns None
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Validation guards
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # PersistenceError wrapping
    # -----------------------------------------------------------------------

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
# delete_rate_limit_state
# ===========================================================================


class TestDeleteRateLimitState:

    # -----------------------------------------------------------------------
    # Success path — no return value, no exception
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Validation guards
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # PersistenceError on DB failure
    # -----------------------------------------------------------------------

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
