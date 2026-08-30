from __future__ import annotations

from review.policyoverrideservice import PolicyOverrideService
from v.review.policyevaluator import PolicyOverride


def test_policy_override_service_accepts_canonical_policy_override() -> None:
    override = PolicyOverride(
        override_id="ovr-001",
        target_field="risk_level",
        target_value="high",
        add_reasons=["manual override applied"],
        enabled=True,
    )

    service = PolicyOverrideService()
    saved = service.add_override(override)

    assert saved.override_id == "ovr-001"
    assert service.get_override("ovr-001") == override
    assert service.find_applicable({"risk_level": "high"}) == [override]


def test_policy_override_service_tracks_enabled_state() -> None:
    service = PolicyOverrideService(
        [
            PolicyOverride(
                override_id="ovr-002",
                target_field="decision",
                target_value="review",
                add_reasons=["manual review"],
                enabled=True,
            )
        ]
    )

    updated = service.set_enabled("ovr-002", False)
    assert updated.enabled is False
    assert service.count(enabled_only=True) == 0
