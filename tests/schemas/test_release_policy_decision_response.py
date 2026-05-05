from __future__ import annotations

import pytest
from pydantic import ValidationError

from models.release_policy_decision import ReleasePolicyDecision


def test_release_policy_decision_accepts_valid_payload() -> None:
    decision = ReleasePolicyDecision(
        decision_id="release-policy-production-20260427T220000Z",
        channel="production",
        allowed=True,
        requested_version="1.0.0",
        minimum_upgrade_from="1.0.0",
        decision_reason="all checks passed",
        actor="pytest",
        metadata={"source": "unit-test"},
    )

    assert decision.channel == "production"
    assert decision.allowed is True
    assert decision.requested_version == "1.0.0"
    assert decision.minimum_upgrade_from == "1.0.0"
    assert decision.actor == "pytest"
    assert decision.metadata["source"] == "unit-test"


def test_release_policy_decision_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ReleasePolicyDecision(
            decision_id="release-policy-production-20260427T220000Z",
            channel="production",
            allowed=True,
            requested_version="1.0.0",
            minimum_upgrade_from="1.0.0",
            decision_reason="all checks passed",
            actor="pytest",
            metadata={},
            unexpected_field="forbidden",
        )


def test_release_policy_decision_rejects_blank_required_strings() -> None:
    with pytest.raises(ValidationError):
        ReleasePolicyDecision(
            decision_id="release-policy-production-20260427T220000Z",
            channel="production",
            allowed=True,
            requested_version="   ",
            minimum_upgrade_from="1.0.0",
            decision_reason="all checks passed",
            actor="pytest",
            metadata={},
        )


def test_release_policy_decision_requires_valid_channel() -> None:
    with pytest.raises(ValidationError):
        ReleasePolicyDecision(
            decision_id="release-policy-production-20260427T220000Z",
            channel="invalid",
            allowed=True,
            requested_version="1.0.0",
            minimum_upgrade_from="1.0.0",
            decision_reason="all checks passed",
            actor="pytest",
            metadata={},
        )