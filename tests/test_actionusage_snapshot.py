from __future__ import annotations

from app.services.actionexecuteservice import ActionExecuteService


class FakeUsageSnapshotService:
    def get_usage_snapshot(self, *, owner_key: str) -> dict[str, object]:
        return {
            "owner_key": owner_key,
            "plan": "starter",
            "package_id": "sub_snapshot",
            "remaining_units": 6,
            "wallet_balance": 4,
            "allowed": True,
            "active": True,
        }


def test_action_usage_snapshot_returns_expected_fields() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotService())

    snapshot = service.get_usage_snapshot(owner_key="owner-401")

    assert snapshot["owner_key"] == "owner-401"
    assert snapshot["plan"] == "starter"
    assert snapshot["package_id"] == "sub_snapshot"
    assert snapshot["remaining_units"] == 6
    assert snapshot["wallet_balance"] == 4
    assert snapshot["allowed"] is True
    assert snapshot["active"] is True


def test_action_usage_snapshot_ownerkey_changes_per_request() -> None:
    service = ActionExecuteService(usage_metering_service=FakeUsageSnapshotService())

    first = service.get_usage_snapshot(owner_key="owner-402")
    second = service.get_usage_snapshot(owner_key="owner-403")

    assert first["owner_key"] == "owner-402"
    assert second["owner_key"] == "owner-403"
    assert first["package_id"] == second["package_id"]
