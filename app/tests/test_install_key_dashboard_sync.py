from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.services.install_key_dashboard_sync import InstallKeyDashboardSyncService


def _record(*, key_id: str, owner_key: str, program: str, active: bool = True, masked_key: str = "ic_install_demo...abcd", payment_status: str = "paid", entitlements_status: str = "active", issued_after_payment: bool = True, units_consumed: int = 12, metadata: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        key_id=key_id,
        owner_key=owner_key,
        program=program,
        active=active,
        masked_key=masked_key,
        payment_status=payment_status,
        entitlements_status=entitlements_status,
        issued_after_payment=issued_after_payment,
        units_consumed=units_consumed,
        metadata=metadata or {},
    )


def test_dashboard_sync_maps_paid_runtime_keys_to_summary() -> None:
    service = InstallKeyDashboardSyncService()
    owner_key = "owner_dash_001"

    install_keys = [
        _record(key_id="ik_openclaw_1", owner_key=owner_key, program="openclaw", masked_key="ic_install_openclaw_...abcd", units_consumed=40),
        _record(key_id="ik_hermes_1", owner_key=owner_key, program="hermes", masked_key="ic_install_hermes_...efgh", units_consumed=21),
        _record(key_id="ik_security_1", owner_key=owner_key, program="security_guardian", active=False, masked_key="ic_install_security_guardian_...xyz", metadata={"shared_family": True}),
    ]

    wallet_summary = {
        "owner_key": owner_key,
        "balance_units": 120,
        "total_consumed_units": 61,
        "total_blocked_attacks": 7,
        "install_key_usage": {
            "ik_openclaw_1": {
                "key_id": "ik_openclaw_1",
                "owner_key": owner_key,
                "program": "openclaw",
                "total_consumed_units": 40,
                "total_blocked_attacks": 4,
                "metadata": {"action_type": "prompt"},
            },
            "ik_hermes_1": {
                "key_id": "ik_hermes_1",
                "owner_key": owner_key,
                "program": "hermes",
                "total_consumed_units": 21,
                "total_blocked_attacks": 3,
                "metadata": {"action_type": "tool_call"},
            },
        },
    }

    summary = service.build_dashboard_summary(owner_key=owner_key, install_keys=install_keys, wallet_summary=wallet_summary)

    assert summary["owner_key"] == owner_key
    assert summary["wallet_total_units"] == 120
    assert summary["blocked_activity_total"] == 0
    assert summary["runtime_coverage"]["openclaw"] is True
    assert summary["runtime_coverage"]["hermes"] is True
    assert "security_guardian" not in summary["runtime_coverage"]
    assert {slot["program"] for slot in summary["install_key_slots"]} == {"openclaw", "hermes"}
    assert all(slot["program"] != "security_guardian" for slot in summary["install_key_slots"])
    assert summary["install_key_slots"][0]["masked_key"] == "ic_install_openclaw_...abcd"


def test_dashboard_sync_maps_runtime_usage_and_sanitized_attack_events() -> None:
    service = InstallKeyDashboardSyncService()
    owner_key = "owner_dash_usage"
    today = datetime.now(UTC)
    today_key = today.date().isoformat()
    yesterday_key = (today.date() - timedelta(days=1)).isoformat()

    summary = service.build_dashboard_summary(
        owner_key=owner_key,
        install_keys=[
            _record(key_id="ik_cursor_usage", owner_key=owner_key, program="cursor"),
        ],
        wallet_summary={
            "owner_key": owner_key,
            "balance_units": 90,
            "install_key_usage": {
                "ik_cursor_usage": {
                    "key_id": "ik_cursor_usage",
                    "owner_key": owner_key,
                    "program": "cursor",
                    "total_consumed_units": 8,
                    "total_blocked_attacks": 2,
                    "units_used_today": 3,
                    "units_used_this_week": 8,
                    "usage_by_day": {yesterday_key: 5, today_key: 3},
                },
            },
        },
        audit_events=[
            SimpleNamespace(
                event_id="audit-blocked-1",
                event_type="policy_decision",
                severity="high",
                created_at=today,
                verdict="block",
                metadata={"category": "prompt-injection"},
                summary="sensitive prompt contents are not dashboard metadata",
            ),
            SimpleNamespace(
                event_id="audit-allowed-1",
                event_type="policy_decision",
                severity="low",
                created_at=today,
                verdict="allow",
                metadata={},
            ),
        ],
    )

    assert summary["units_today"] == 3
    assert summary["units_week"] == 8
    assert summary["daily_usage"][-2]["date"] == yesterday_key
    assert summary["daily_usage"][-2]["units"] == 5
    assert summary["daily_usage"][-1]["date"] == today_key
    assert summary["daily_usage"][-1]["units"] == 3
    assert len(summary["attacks"]) == 1
    assert summary["attacks"][0]["id"] == "audit-blocked-1"
    assert summary["blocked_activity_total"] == 1
    assert summary["attacks"][0]["title"] == "Prompt Injection"
    assert "sensitive prompt contents" not in str(summary["attacks"][0])


def test_dashboard_sync_rejects_generic_platform_auth_as_owner() -> None:
    service = InstallKeyDashboardSyncService()

    try:
        service.build_dashboard_summary(owner_key="ghp_abc123", install_keys=[], wallet_summary={})
        raise AssertionError("expected ValueError for generic platform auth ownership")
    except ValueError as exc:
        assert "owner_key" in str(exc).lower()


def test_dashboard_sync_ignores_non_runtime_connector_entries() -> None:
    service = InstallKeyDashboardSyncService()
    owner_key = "owner_dash_002"

    summary = service.build_dashboard_summary(
        owner_key=owner_key,
        install_keys=[
            _record(key_id="ik_security_2", owner_key=owner_key, program="security_guardian", active=False),
            _record(key_id="ik_cursor_2", owner_key=owner_key, program="cursor", active=True),
        ],
        wallet_summary={
            "owner_key": owner_key,
            "balance_units": 250,
            "total_consumed_units": 15,
            "total_blocked_attacks": 2,
            "install_key_usage": {
                "ik_cursor_2": {
                    "key_id": "ik_cursor_2",
                    "owner_key": owner_key,
                    "program": "cursor",
                    "total_consumed_units": 15,
                    "total_blocked_attacks": 2,
                    "metadata": {"action_type": "prompt"},
                }
            },
        },
    )

    assert summary["runtime_coverage"]["cursor"] is True
    assert "security_guardian" not in summary["runtime_coverage"]
    assert all(slot["program"] != "security_guardian" for slot in summary["install_key_slots"])


def test_dashboard_sync_only_keeps_current_paid_runtime_keys() -> None:
    service = InstallKeyDashboardSyncService()
    owner_key = "owner_dash_003"

    summary = service.build_dashboard_summary(
        owner_key=owner_key,
        install_keys=[
            _record(
                key_id="ik_openclaw_unpaid",
                owner_key=owner_key,
                program="openclaw",
                active=False,
                payment_status="unpaid",
                entitlements_status="not_active",
                issued_after_payment=False,
            ),
            _record(
                key_id="ik_cursor_paid",
                owner_key=owner_key,
                program="cursor",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
            ),
            _record(
                key_id="ik_copilot_foreign",
                owner_key="ghp_foreigntoken",
                program="copilot",
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
            ),
        ],
        wallet_summary={
            "owner_key": owner_key,
            "balance_units": 200,
            "total_consumed_units": 30,
            "total_blocked_attacks": 5,
            "install_key_usage": {
                "ik_openclaw_unpaid": {
                    "key_id": "ik_openclaw_unpaid",
                    "owner_key": owner_key,
                    "program": "openclaw",
                    "total_consumed_units": 10,
                    "total_blocked_attacks": 1,
                    "metadata": {"action_type": "prompt"},
                },
                "ik_cursor_paid": {
                    "key_id": "ik_cursor_paid",
                    "owner_key": owner_key,
                    "program": "cursor",
                    "total_consumed_units": 20,
                    "total_blocked_attacks": 3,
                    "metadata": {"action_type": "tool_call"},
                },
                "ik_copilot_foreign": {
                    "key_id": "ik_copilot_foreign",
                    "owner_key": "ghp_foreigntoken",
                    "program": "copilot",
                    "total_consumed_units": 99,
                    "total_blocked_attacks": 2,
                    "metadata": {"action_type": "prompt"},
                },
            },
        },
    )

    assert {slot["program"] for slot in summary["install_key_slots"]} == {"cursor"}
    assert summary["runtime_coverage"]["cursor"] is True
    assert "openclaw" not in {slot["program"] for slot in summary["install_key_slots"]}
    assert "copilot" not in {slot["program"] for slot in summary["install_key_slots"]}
