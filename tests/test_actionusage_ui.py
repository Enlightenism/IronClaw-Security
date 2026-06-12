from __future__ import annotations

from app.ui.actionusage import (
    _format_value,
    _infer_tone,
    build_action_usage_view,
)
from app.ui.actionusagedetail import (
    _format_detail_value,
    _infer_detail_tone,
    build_action_usage_detail_view,
)
from app.ui.actionusagetest import build_action_usage_test_view

# ---------------------------------------------------------------------------
# _format_value
# ---------------------------------------------------------------------------


def test_format_value_none_returns_dash() -> None:
    assert _format_value(None) == "—"


def test_format_value_bool_true() -> None:
    assert _format_value(True) == "Yes"


def test_format_value_bool_false() -> None:
    assert _format_value(False) == "No"


def test_format_value_int() -> None:
    assert _format_value(42) == "42"


def test_format_value_string_passthrough() -> None:
    assert _format_value("pro") == "pro"


# ---------------------------------------------------------------------------
# _infer_tone (actionusage.py)
# ---------------------------------------------------------------------------


def test_infer_tone_remaining_units_positive_is_good() -> None:
    assert _infer_tone("remaining_units", 5) == "good"


def test_infer_tone_remaining_units_zero_is_warning() -> None:
    assert _infer_tone("remaining_units", 0) == "warning"


def test_infer_tone_wallet_balance_positive_is_good() -> None:
    assert _infer_tone("wallet_balance", 1) == "good"


def test_infer_tone_wallet_balance_zero_is_warning() -> None:
    assert _infer_tone("wallet_balance", 0) == "warning"


def test_infer_tone_allowed_true_is_good() -> None:
    assert _infer_tone("allowed", True) == "good"


def test_infer_tone_allowed_false_is_warning() -> None:
    assert _infer_tone("allowed", False) == "warning"


def test_infer_tone_unknown_label_is_neutral() -> None:
    assert _infer_tone("tokens_in_wallet", 99) == "neutral"


def test_infer_tone_non_numeric_remaining_units_is_neutral() -> None:
    assert _infer_tone("remaining_units", "not-a-number") == "neutral"


# ---------------------------------------------------------------------------
# _format_detail_value
# ---------------------------------------------------------------------------


def test_format_detail_value_none_returns_dash() -> None:
    assert _format_detail_value(None) == "—"


def test_format_detail_value_bool_true() -> None:
    assert _format_detail_value(True) == "Yes"


def test_format_detail_value_bool_false() -> None:
    assert _format_detail_value(False) == "No"


def test_format_detail_value_list_joined() -> None:
    assert _format_detail_value(["prepaid", "active"]) == "prepaid, active"


def test_format_detail_value_empty_list() -> None:
    assert _format_detail_value([]) == "[]"


def test_format_detail_value_dict_sorted() -> None:
    assert _format_detail_value({"region": "mx", "tier": "edge"}) == "region=mx, tier=edge"


def test_format_detail_value_empty_dict() -> None:
    assert _format_detail_value({}) == "{}"


def test_format_detail_value_int() -> None:
    assert _format_detail_value(7) == "7"


# ---------------------------------------------------------------------------
# _infer_detail_tone
# ---------------------------------------------------------------------------


def test_infer_detail_tone_remaining_units_positive_is_good() -> None:
    assert _infer_detail_tone("remaining_units", 10) == "good"


def test_infer_detail_tone_remaining_units_zero_is_warning() -> None:
    assert _infer_detail_tone("remaining_units", 0) == "warning"


def test_infer_detail_tone_remaining_units_negative_is_critical() -> None:
    assert _infer_detail_tone("remaining_units", -1) == "critical"


def test_infer_detail_tone_wallet_balance_zero_is_warning() -> None:
    assert _infer_detail_tone("wallet_balance", 0) == "warning"


def test_infer_detail_tone_allowed_true_is_good() -> None:
    assert _infer_detail_tone("allowed", True) == "good"


def test_infer_detail_tone_status_authorized_is_good() -> None:
    assert _infer_detail_tone("status", "authorized") == "good"


def test_infer_detail_tone_status_denied_is_critical() -> None:
    assert _infer_detail_tone("status", "denied") == "critical"


def test_infer_detail_tone_status_review_is_warning() -> None:
    assert _infer_detail_tone("status", "review") == "warning"


def test_infer_detail_tone_tokens_in_wallet_unknown_is_neutral() -> None:
    assert _infer_detail_tone("tokens_in_wallet", 500) == "neutral"


# ---------------------------------------------------------------------------
# build_action_usage_view
# ---------------------------------------------------------------------------


def test_build_action_usage_view_creates_expected_stats() -> None:
    view = build_action_usage_view(
        ownerkey="owner-001",
        snapshot={
            "plan": "pro",
            "package_id": "sub_123",
            "remaining_units": 12,
            "wallet_balance": 7,
            "allowed": True,
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage"
    assert view.ownerkey == "owner-001"
    assert len(view.stats) >= 5
    assert view.metadata["requested_by"] == "tester"
    assert any(item.label == "remaining_units" and item.value == "12" for item in view.stats)
    assert any(item.label == "wallet_balance" and item.tone == "good" for item in view.stats)
    assert any(item.label == "allowed" and item.tone == "good" for item in view.stats)


def test_build_action_usage_view_tokens_in_wallet_present() -> None:
    view = build_action_usage_view(
        ownerkey="owner-tok",
        snapshot={
            "plan": "team",
            "remaining_units": 5,
            "tokens_in_wallet": 125_000,
        },
        requested_by="tester",
    )
    stat = next((s for s in view.stats if s.label == "tokens_in_wallet"), None)
    assert stat is not None
    assert stat.value == "125000"
    assert stat.tone == "neutral"


def test_build_action_usage_view_preferred_order_respected() -> None:
    view = build_action_usage_view(
        ownerkey="owner-ord",
        snapshot={
            "wallet_balance": 3,
            "plan": "starter",
            "remaining_units": 1,
        },
        requested_by=None,
    )
    labels = [s.label for s in view.stats]
    assert labels.index("plan") < labels.index("remaining_units")
    assert labels.index("remaining_units") < labels.index("wallet_balance")


def test_build_action_usage_view_ownerkey_stripped() -> None:
    view = build_action_usage_view(
        ownerkey="  owner-ws  ",
        snapshot={"plan": "pro"},
        requested_by=None,
    )
    assert view.ownerkey == "owner-ws"


def test_build_action_usage_view_none_snapshot_gives_empty_stats() -> None:
    view = build_action_usage_view(
        ownerkey="owner-empty",
        snapshot=None,
        requested_by=None,
    )
    assert view.stats == []
    assert view.snapshot == {}


# ---------------------------------------------------------------------------
# build_action_usage_detail_view
# ---------------------------------------------------------------------------


def test_build_action_usage_detail_view_formats_rows() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-002",
        snapshot={
            "plan": "starter",
            "status": "authorized",
            "remaining_units": 0,
            "flags": ["prepaid", "active"],
            "context": {"region": "mx", "tier": "edge"},
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage Detail"
    assert view.ownerkey == "owner-002"
    assert view.metadata["requested_by"] == "tester"
    assert any(row.key == "status" and row.tone == "good" for row in view.rows)
    assert any(row.key == "remaining_units" and row.tone == "warning" for row in view.rows)
    assert any(row.key == "flags" and row.value == "prepaid, active" for row in view.rows)
    assert any(row.key == "context" and row.value == "region=mx, tier=edge" for row in view.rows)


def test_build_action_usage_detail_view_tokens_in_wallet_present() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-dtok",
        snapshot={
            "plan": "enterprise",
            "remaining_units": 50,
            "tokens_in_wallet": 1_250_000,
        },
        requested_by="tester",
    )
    row = next((r for r in view.rows if r.key == "tokens_in_wallet"), None)
    assert row is not None
    assert row.value == "1250000"
    assert row.tone == "neutral"


def test_build_action_usage_detail_view_preferred_order_respected() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-dord",
        snapshot={
            "status": "active",
            "wallet_balance": 2,
            "plan": "pro",
            "remaining_units": 3,
        },
        requested_by=None,
    )
    keys = [r.key for r in view.rows]
    assert keys.index("plan") < keys.index("remaining_units")
    assert keys.index("remaining_units") < keys.index("wallet_balance")
    assert keys.index("wallet_balance") < keys.index("status")


def test_build_action_usage_detail_view_ownerkey_stripped() -> None:
    view = build_action_usage_detail_view(
        ownerkey="  owner-dws  ",
        snapshot={"plan": "pro"},
        requested_by=None,
    )
    assert view.ownerkey == "owner-dws"


def test_build_action_usage_detail_view_none_snapshot_gives_empty_rows() -> None:
    view = build_action_usage_detail_view(
        ownerkey="owner-dempty",
        snapshot=None,
        requested_by=None,
    )
    assert view.rows == []
    assert view.snapshot == {}


# ---------------------------------------------------------------------------
# build_action_usage_test_view
# ---------------------------------------------------------------------------


def test_build_action_usage_test_view_combines_summary_detail_and_checks() -> None:
    view = build_action_usage_test_view(
        ownerkey="owner-003",
        snapshot={
            "plan": "enterprise",
            "remaining_units": 25,
            "wallet_balance": 100,
        },
        requested_by="tester",
    )

    assert view.title == "Action Usage Test"
    assert view.ownerkey == "owner-003"
    assert view.summary.ownerkey == "owner-003"
    assert view.detail.ownerkey == "owner-003"
    assert view.metadata["requested_by"] == "tester"
    assert "snapshot_loaded" in view.checks
    assert "remaining_units_present" in view.checks
    assert "wallet_balance_present" in view.checks
    assert "plan_present" in view.checks


def test_build_action_usage_test_view_tokens_in_wallet_surfaced() -> None:
    view = build_action_usage_test_view(
        ownerkey="owner-tw",
        snapshot={
            "plan": "team",
            "remaining_units": 10,
            "wallet_balance": 50,
            "tokens_in_wallet": 250_000,
        },
        requested_by="tester",
    )
    summary_stat = next((s for s in view.summary.stats if s.label == "tokens_in_wallet"), None)
    detail_row = next((r for r in view.detail.rows if r.key == "tokens_in_wallet"), None)
    assert summary_stat is not None, "tokens_in_wallet must appear in summary stats"
    assert summary_stat.value == "250000"
    assert detail_row is not None, "tokens_in_wallet must appear in detail rows"
    assert detail_row.value == "250000"


def test_build_action_usage_test_view_empty_snapshot_emits_missing_checks() -> None:
    view = build_action_usage_test_view(
        ownerkey="owner-empty",
        snapshot=None,
        requested_by=None,
    )
    assert "snapshot_empty" in view.checks
    assert "remaining_units_missing" in view.checks
    assert "wallet_balance_missing" in view.checks
    assert "plan_missing" in view.checks


def test_build_action_usage_test_view_ownerkey_propagated_to_sub_views() -> None:
    view = build_action_usage_test_view(
        ownerkey="  owner-prop  ",
        snapshot={"plan": "pro", "remaining_units": 1, "wallet_balance": 5},
        requested_by=None,
    )
    assert view.ownerkey == "owner-prop"
    assert view.summary.ownerkey == "owner-prop"
    assert view.detail.ownerkey == "owner-prop"
