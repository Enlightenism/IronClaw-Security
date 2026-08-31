from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from pydantic import ValidationError
import pytest

from app.schemas.install_key import (
    InstallKeyDashboardSummary,
    InstallKeyIssueEvent,
    InstallKeyRecord,
    InstallKeyUsageEvent,
)

_NOW = "2026-06-16T12:00:00+00:00"


def _record_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "key_id": "ik_abc123",
        "owner_key": "user@ironclaw.test",
        "subscription_id": "sub_123",
        "program": "openclaw",
        "masked_key": "ic_install_openclaw_...d3f4",
        "label": "prod-openclaw",
        "active": True,
        "payment_status": "paid",
        "entitlements_status": "active",
        "issued_after_payment": True,
        "org_id": "org_42",
        "customer_id": "cus_001",
        "units_consumed": 12,
        "created_at": _NOW,
        "last_used_at": _NOW,
        "revoked_at": None,
        "purchase_reference": "purchase_ref_123",
        "checkout_session_id": "cs_123",
        "metadata": {"env": "prod", "tier": "team"},
    }
    base.update(overrides)
    return base


def _issue_event_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_id": "evt_iss_001",
        "event_type": "install_key_issued",
        "key_id": "ik_abc123",
        "owner_key": "user@ironclaw.test",
        "subscription_id": "sub_123",
        "program": "openclaw",
        "masked_key": "ic_install_openclaw_...d3f4",
        "label": "prod-openclaw",
        "org_id": "org_42",
        "customer_id": "cus_001",
        "payment_status": "paid",
        "entitlements_status": "active",
        "issued_after_payment": True,
        "purchase_reference": "purchase_ref_123",
        "checkout_session_id": "cs_123",
        "issued_at": _NOW,
        "source": "billing",
        "metadata": {"plan_code": "team-25k"},
    }
    base.update(overrides)
    return base


def _usage_event_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "event_id": "evt_use_001",
        "event_type": "install_key_usage_recorded",
        "key_id": "ik_abc123",
        "owner_key": "user@ironclaw.test",
        "program": "openclaw",
        "units": 5,
        "units_remaining": 95,
        "balance_after": 95,
        "recorded_at": _NOW,
        "source": "runtime",
        "metadata": {"action": "guard.prompt", "risk": "low"},
    }
    base.update(overrides)
    return base


def _dashboard_payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "owner_key": "user@ironclaw.test",
        "has_active_subscription": True,
        "total_keys": 2,
        "active_keys": 1,
        "total_units_consumed": 25,
        "total_blocked_attacks": 4,
        "wallet_balance_units": 75,
        "last_used_at": _NOW,
        "keys": [
            InstallKeyRecord(**_record_payload()),
            InstallKeyRecord(
                **_record_payload(
                    key_id="ik_def456",
                    program="claude_code",
                    masked_key="ic_install_claude_code_...f2a1",
                    label="claude-prod",
                    units_consumed=13,
                    metadata={"env": "prod"},
                )
            ),
        ],
        "by_program": {"openclaw": 1, "claude_code": 1},
        "metadata": {"status": "ok"},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# InstallKeyRecord
# ---------------------------------------------------------------------------


def test_install_key_record_valid_minimal_payload():
    record = InstallKeyRecord(**_record_payload())
    assert record.key_id == "ik_abc123"
    assert record.owner_key == "user@ironclaw.test"
    assert record.program == "openclaw"
    assert record.active is True
    assert record.payment_status == "paid"
    assert record.entitlements_status == "active"
    assert record.issued_after_payment is True
    assert record.org_id == "org_42"
    assert record.customer_id == "cus_001"
    assert record.purchase_reference == "purchase_ref_123"
    assert record.checkout_session_id == "cs_123"
    assert record.units_consumed == 12
    assert record.metadata["env"] == "prod"


def test_install_key_record_accepts_hermes_program():
    record = InstallKeyRecord(**_record_payload(program="hermes", masked_key="ic_install_hermes_...d3f4", label="hermes-prod"))
    assert record.program == "hermes"
    assert record.masked_key == "ic_install_hermes_...d3f4"
    assert record.label == "hermes-prod"


def test_install_key_record_rejects_unknown_program():
    with pytest.raises(ValidationError, match="program"):
        InstallKeyRecord(**_record_payload(program="gpt4"))


def test_install_key_record_rejects_negative_units_consumed():
    with pytest.raises(ValidationError):
        InstallKeyRecord(**_record_payload(units_consumed=-1))


def test_install_key_record_accepts_zero_units_consumed():
    record = InstallKeyRecord(**_record_payload(units_consumed=0))
    assert record.units_consumed == 0


def test_install_key_record_accepts_optional_last_used_at_none():
    record = InstallKeyRecord(**_record_payload(last_used_at=None))
    assert record.last_used_at is None


def test_install_key_record_requires_created_at():
    payload = _record_payload()
    payload.pop("created_at")
    with pytest.raises(ValidationError):
        InstallKeyRecord(**payload)


def test_install_key_record_from_core_accepts_dict():
    obj = InstallKeyRecord.from_core(_record_payload())
    assert obj.key_id == "ik_abc123"
    assert obj.program == "openclaw"
    assert obj.metadata["env"] == "prod"


def test_install_key_record_from_core_accepts_public_dict_object():
    payload = SimpleNamespace(**_record_payload())
    obj = InstallKeyRecord.from_core(payload)
    assert obj.key_id == "ik_abc123"
    assert obj.program == "openclaw"


def test_install_key_record_from_core_accepts_db_row_like_object():
    payload = SimpleNamespace(**_record_payload())
    obj = InstallKeyRecord.from_core(payload)
    assert obj.masked_key == "ic_install_openclaw_...d3f4"


def test_install_key_record_from_core_accepts_to_db_row_like_object():
    row = _record_payload()
    record = InstallKeyRecord(**row)
    model = InstallKeyRecord.from_core(record)
    assert model.key_id == row["key_id"]
    assert model.program == row["program"]


def test_install_key_record_from_core_handles_non_dict_metadata():
    payload = _record_payload(metadata="raw-blob")
    obj = InstallKeyRecord.from_core(payload)
    assert obj.metadata == {"value": "raw-blob"}


# ---------------------------------------------------------------------------
# InstallKeyIssueEvent
# ---------------------------------------------------------------------------


def test_install_key_issue_event_valid():
    event = InstallKeyIssueEvent(**_issue_event_payload())
    assert event.event_type == "install_key_issued"
    assert event.program == "openclaw"
    assert event.payment_status == "paid"
    assert event.entitlements_status == "active"
    assert event.issued_after_payment is True
    assert event.customer_id == "cus_001"
    assert event.purchase_reference == "purchase_ref_123"
    assert event.checkout_session_id == "cs_123"


def test_install_key_issue_event_rejects_unknown_program():
    with pytest.raises(ValidationError, match="program"):
        InstallKeyIssueEvent(**_issue_event_payload(program="gpt4"))


def test_install_key_issue_event_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="event_type"):
        InstallKeyIssueEvent(**_issue_event_payload(event_type="install_key_unknown"))


def test_install_key_issue_event_requires_issued_at():
    payload = _issue_event_payload()
    payload.pop("issued_at")
    with pytest.raises(ValidationError):
        InstallKeyIssueEvent(**payload)


def test_install_key_issue_event_defaults_to_issued_type_when_none():
    payload = _issue_event_payload()
    payload["event_type"] = None
    event = InstallKeyIssueEvent(**payload)
    assert event.event_type == "install_key_issued"


def test_install_key_issue_event_accepts_revoked_event_type():
    event = InstallKeyIssueEvent(**_issue_event_payload(event_type="install_key_revoked"))
    assert event.event_type == "install_key_revoked"


def test_install_key_issue_event_accepts_provisioned_event_type():
    event = InstallKeyIssueEvent(**_issue_event_payload(event_type="install_key_provisioned"))
    assert event.event_type == "install_key_provisioned"


# ---------------------------------------------------------------------------
# InstallKeyUsageEvent
# ---------------------------------------------------------------------------


def test_install_key_usage_event_valid():
    event = InstallKeyUsageEvent(**_usage_event_payload())
    assert event.event_type == "install_key_usage_recorded"
    assert event.units == 5
    assert event.units_remaining == 95
    assert event.balance_after == 95


def test_install_key_usage_event_rejects_zero_units():
    with pytest.raises(ValidationError):
        InstallKeyUsageEvent(**_usage_event_payload(units=0))


def test_install_key_usage_event_rejects_negative_units():
    with pytest.raises(ValidationError):
        InstallKeyUsageEvent(**_usage_event_payload(units=-1))


def test_install_key_usage_event_rejects_unknown_program():
    with pytest.raises(ValidationError, match="program"):
        InstallKeyUsageEvent(**_usage_event_payload(program="gpt4"))


def test_install_key_usage_event_rejects_unknown_event_type():
    with pytest.raises(ValidationError, match="event_type"):
        InstallKeyUsageEvent(**_usage_event_payload(event_type="usage.unknown"))


def test_install_key_usage_event_requires_recorded_at():
    payload = _usage_event_payload()
    payload.pop("recorded_at")
    with pytest.raises(ValidationError):
        InstallKeyUsageEvent(**payload)


def test_install_key_usage_event_accepts_default_type_when_none():
    payload = _usage_event_payload()
    payload["event_type"] = None
    event = InstallKeyUsageEvent(**payload)
    assert event.event_type == "install_key_usage_recorded"


# ---------------------------------------------------------------------------
# InstallKeyDashboardSummary
# ---------------------------------------------------------------------------


def test_install_key_dashboard_summary_valid():
    summary = InstallKeyDashboardSummary(**_dashboard_payload())
    assert summary.owner_key == "user@ironclaw.test"
    assert summary.has_active_subscription is True
    assert summary.total_keys == 2
    assert summary.active_keys == 1
    assert summary.total_units_consumed == 25
    assert summary.total_blocked_attacks == 4
    assert summary.wallet_balance_units == 75
    assert summary.by_program == {"openclaw": 1, "claude_code": 1}
    assert len(summary.keys) == 2


def test_install_key_dashboard_summary_defaults_to_empty_by_program():
    summary = InstallKeyDashboardSummary(
        owner_key="user@ironclaw.test",
        has_active_subscription=False,
    )
    assert summary.by_program == {}
    assert summary.keys == []


def test_install_key_dashboard_summary_normalizes_program_counts():
    summary = InstallKeyDashboardSummary(
        owner_key="user@ironclaw.test",
        has_active_subscription=True,
        total_keys=2,
        active_keys=2,
        by_program={"openclaw": 1, "claude_code": 1},
    )
    assert summary.by_program == {"openclaw": 1, "claude_code": 1}


def test_install_key_dashboard_summary_rejects_unknown_program_in_by_program():
    with pytest.raises(ValidationError, match="program"):
        InstallKeyDashboardSummary(
            owner_key="user@ironclaw.test",
            has_active_subscription=True,
            by_program={"openclaw": 1, "gpt4": 1},
        )


def test_install_key_dashboard_summary_rejects_non_dict_by_program():
    with pytest.raises(ValidationError, match="by_program"):
        InstallKeyDashboardSummary(
            owner_key="user@ironclaw.test",
            has_active_subscription=True,
            by_program=["openclaw"],
        )


def test_install_key_dashboard_summary_accepts_last_used_at_none():
    summary = InstallKeyDashboardSummary(
        owner_key="user@ironclaw.test",
        has_active_subscription=True,
        last_used_at=None,
    )
    assert summary.last_used_at is None


# ---------------------------------------------------------------------------
# Cross-model sanity checks
# ---------------------------------------------------------------------------


def test_install_key_models_round_trip_from_core_record_to_summary():
    record = InstallKeyRecord(**_record_payload())
    summary = InstallKeyDashboardSummary(
        owner_key=record.owner_key,
        has_active_subscription=True,
        total_keys=1,
        active_keys=1,
        total_units_consumed=record.units_consumed,
        wallet_balance_units=100,
        last_used_at=record.last_used_at,
        keys=[record],
        by_program={record.program: 1},
    )
    assert summary.keys[0].key_id == record.key_id
    assert summary.by_program[record.program] == 1


def test_install_key_usage_event_must_be_positive_integer():
    with pytest.raises(ValidationError):
        InstallKeyUsageEvent(**_usage_event_payload(units=0))
        InstallKeyUsageEvent(**_usage_event_payload(units=-1))
