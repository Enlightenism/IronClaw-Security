from __future__ import annotations

from app.services.actionexecuteservice import ActionExecuteService


class FakeUsageSnapshotService:
    def get_usage_snapshot(self, *, owner_key: str) -> dict[str, object]:
        return {
            "owner_key": owner_key,
            "has_active_subscription": True,
            "plan": "starter",
            "package_id": "sub_snapshot",
            "unit_limit": 10,
            "units_consumed": 4,
            "remaining_units": 6,
            "tokens_per_unit": 25_000,
            "token_coverage_limit": 250_000,
            "remaining_token_coverage": 150_000,
            "wallet_balance_units": 4,
            "checked_at": "2026-01-01T00:00:00Z",
        }


class FakeUsageSnapshotServiceNoSubscription:
    def get_usage_snapshot(self, *, owner_key: str) -> dict[str, object]:
        return {
            "owner_key": owner_key,
            "has_active_subscription": False,
            "plan": None,
            "package_id": None,
            "unit_limit": 0,
            "units_consumed": 0,
            "remaining_units": 0,
            "tokens_per_unit": 25_000,
            "token_coverage_limit": 0,
            "remaining_token_coverage": 0,
            "wallet_balance_units": 0,
            "checked_at": "2026-01-01T00:00:00Z",
        }


def test_action_usage_snapshot_returns_expected_fields() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotService())

    snapshot = service.get_usage_snapshot(owner_key="owner-401")

    assert snapshot["owner_key"] == "owner-401"
    assert snapshot["has_active_subscription"] is True
    assert snapshot["plan"] == "starter"
    assert snapshot["package_id"] == "sub_snapshot"
    assert snapshot["unit_limit"] == 10
    assert snapshot["units_consumed"] == 4
    assert snapshot["remaining_units"] == 6
    assert snapshot["tokens_per_unit"] == 25_000
    assert snapshot["token_coverage_limit"] == 250_000
    assert snapshot["remaining_token_coverage"] == 150_000
    assert snapshot["wallet_balance_units"] == 4
    assert snapshot["checked_at"] == "2026-01-01T00:00:00Z"


def test_action_usage_snapshot_ownerkey_changes_per_request() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotService())

    first = service.get_usage_snapshot(owner_key="owner-402")
    second = service.get_usage_snapshot(owner_key="owner-403")

    assert first["owner_key"] == "owner-402"
    assert second["owner_key"] == "owner-403"
    assert first["package_id"] == second["package_id"]
    assert first["tokens_per_unit"] == second["tokens_per_unit"]


def test_action_usage_snapshot_no_subscription_shape() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotServiceNoSubscription())

    snapshot = service.get_usage_snapshot(owner_key="owner-404")

    assert snapshot["owner_key"] == "owner-404"
    assert snapshot["has_active_subscription"] is False
    assert snapshot["plan"] is None
    assert snapshot["package_id"] is None
    assert snapshot["unit_limit"] == 0
    assert snapshot["units_consumed"] == 0
    assert snapshot["remaining_units"] == 0
    assert snapshot["tokens_per_unit"] == 25_000
    assert snapshot["token_coverage_limit"] == 0
    assert snapshot["remaining_token_coverage"] == 0
    assert snapshot["wallet_balance_units"] == 0


def test_action_usage_snapshot_wallet_balance_units_is_canonical_field() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotService())

    snapshot = service.get_usage_snapshot(owner_key="owner-405")

    assert "wallet_balance_units" in snapshot
    assert "wallet_balance" not in snapshot


def test_action_usage_snapshot_token_coverage_fields_present() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotService())

    snapshot = service.get_usage_snapshot(owner_key="owner-406")

    assert "token_coverage_limit" in snapshot
    assert "remaining_token_coverage" in snapshot
    assert snapshot["token_coverage_limit"] == snapshot["unit_limit"] * snapshot["tokens_per_unit"]
    assert snapshot["remaining_token_coverage"] == snapshot["remaining_units"] * snapshot["tokens_per_unit"]
