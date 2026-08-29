from __future__ import annotations

from app.dashboard.overview import (
    DashboardInstallKeySlot,
    DashboardOverview,
    DashboardPlatformFamily,
    build_dashboard_overview,
    dashboard_overview_summary,
    default_dashboard_overview,
)


def test_default_dashboard_overview_includes_platform_families_and_slots() -> None:
    overview = default_dashboard_overview()

    assert overview.platform_families
    assert overview.install_key_slots
    assert [slot.program for slot in overview.install_key_slots] == [
        "openclaw",
        "claude_code",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "security_guardian",
    ]
    assert all(slot.status == "locked" for slot in overview.install_key_slots)
    assert all(slot.payment_status == "unpaid" for slot in overview.install_key_slots)
    assert all(slot.metadata.get("placeholder") == "Keys will be generated after purchase" for slot in overview.install_key_slots)


def test_build_dashboard_overview_rejects_legacy_runtime_labels() -> None:
    overview = build_dashboard_overview(
        {
            "platform_families": [
                {"family": "Standalone IronClaw", "platform": "Standalone IronClaw", "label": "Standalone IronClaw"},
                {"family": "openclaw", "platform": "openclaw", "label": "OpenClaw", "status": "active", "installed": True},
            ],
            "install_key_slots": [
                {"program": "Standalone IronClaw", "label": "Standalone IronClaw", "status": "locked", "masked_key": None, "metadata": {}},
                {"program": "openclaw", "label": "OpenClaw", "status": "active", "active": True, "masked_key": "ic_install_openclaw_...abcd", "payment_status": "paid", "entitlements_status": "active", "metadata": {"placeholder": "Keys will be generated after purchase"}},
            ],
        }
    )

    programs = {slot.program for slot in overview.install_key_slots}
    assert "openclaw" in programs
    assert "standalone_ironclaw" not in programs
    assert "ironclaw" not in programs
    assert all(slot.metadata.get("placeholder") != "Standalone IronClaw" for slot in overview.install_key_slots if slot.metadata)


def test_build_dashboard_overview_normalizes_runtime_slots_and_platform_metadata() -> None:
    overview = build_dashboard_overview(
        {
            "status": "ok",
            "platform_families": [
                {
                    "family": "claude_code",
                    "platform": "claude_code",
                    "label": "Claude Code",
                    "status": "active",
                    "installed": True,
                    "payment_status": "paid",
                    "entitlements_status": "active",
                    "metadata": {"billing": "pro"},
                },
                {
                    "family": "cursor",
                    "platform": "cursor",
                    "label": "Cursor",
                    "status": "locked",
                    "installed": False,
                    "payment_status": "unpaid",
                    "entitlements_status": "not_active",
                },
            ],
            "install_key_slots": [
                {
                    "program": "claude_code",
                    "label": "Claude Code",
                    "status": "active",
                    "active": True,
                    "masked_key": "ic_install_claude_code_...abcd",
                    "payment_status": "paid",
                    "entitlements_status": "active",
                    "issued_after_payment": True,
                    "units_consumed": 7,
                    "metadata": {"key_id": "key_001"},
                },
                {
                    "program": "goose",
                    "label": "Goose",
                    "status": "locked",
                    "active": False,
                    "masked_key": None,
                    "payment_status": "unpaid",
                    "entitlements_status": "not_active",
                    "issued_after_payment": False,
                    "units_consumed": 0,
                    "metadata": {"placeholder": "Keys will be generated after purchase"},
                },
            ],
        }
    )

    assert overview.platform_families[0].family == "claude_code"
    assert overview.platform_families[0].status == "active"
    assert overview.install_key_slots[0].program == "claude_code"
    assert overview.install_key_slots[0].status == "active"
    assert overview.install_key_slots[1].program == "goose"
    assert overview.install_key_slots[1].metadata["placeholder"] == "Keys will be generated after purchase"


def test_dashboard_overview_summary_shares_platform_matrix() -> None:
    slot = DashboardInstallKeySlot(
        key_id="key_123",
        program="copilot",
        label="GitHub Copilot",
        status="active",
        active=True,
        masked_key="ic_install_copilot_...abcd",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        units_consumed=11,
        metadata={"platform": "copilot"},
    )
    family = DashboardPlatformFamily(
        family="copilot",
        platform="copilot",
        label="GitHub Copilot",
        status="active",
        installed=True,
        payment_status="paid",
        entitlements_status="active",
        metadata={"billing": "team"},
    )
    overview = DashboardOverview(
        total_requests=100,
        blocked_actions=4,
        quarantined_actions=2,
        kpis=(),
        alerts=(),
        platform_families=(family,),
        install_key_slots=(slot,),
    )

    summary = dashboard_overview_summary(overview)

    assert summary["platform_families"][0]["family"] == "copilot"
    assert summary["install_key_slots"][0]["program"] == "copilot"
    assert summary["available_install_key_slots"][0]["program"] == "copilot"
    assert summary["coverage"]["protection_rate"] == 6.0
