from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.orchestrator.policyenforcer import build_policy_enforcer


@dataclass(slots=True)
class _BundleVerification:
    valid: bool = True
    allowed: bool = True
    verdict: str = "allow"
    bundle_id: str = "bundle-001"
    version: str = "2026.04.25"
    reasons: list[dict[str, Any]] | None = None
    matched_rules: list[str] | None = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []
        if self.matched_rules is None:
            self.matched_rules = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "bundleid": self.bundle_id,
            "version": self.version,
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
        }


@dataclass(slots=True)
class _OverrideDecision:
    allowed: bool = False
    verdict: str = "none"
    active: bool = False
    reasons: list[dict[str, Any]] | None = None
    matched_rules: list[str] | None = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []
        if self.matched_rules is None:
            self.matched_rules = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "verdict": self.verdict,
            "active": self.active,
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
        }


@dataclass(slots=True)
class _RolloutDecision:
    enabled: bool = True
    allowed: bool = True
    verdict: str = "allow"
    reasons: list[dict[str, Any]] | None = None
    matched_rules: list[str] | None = None

    def __post_init__(self) -> None:
        if self.reasons is None:
            self.reasons = []
        if self.matched_rules is None:
            self.matched_rules = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
        }


class _BundleSigningServiceStub:
    def __init__(self, verification: _BundleVerification | None = None) -> None:
        self.verification = verification or _BundleVerification()
        self.calls: list[dict[str, Any]] = []

    def verify_bundle(self, **kwargs: Any) -> _BundleVerification:
        self.calls.append(dict(kwargs))
        return self.verification


class _PolicyOverrideServiceStub:
    def __init__(self, decision: _OverrideDecision | None = None) -> None:
        self.decision = decision or _OverrideDecision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _OverrideDecision:
        self.calls.append(dict(kwargs))
        return self.decision


class _ReleasePolicyServiceStub:
    def __init__(self, decision: _RolloutDecision | None = None) -> None:
        self.decision = decision or _RolloutDecision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _RolloutDecision:
        self.calls.append(dict(kwargs))
        return self.decision


def _build(
    *,
    verification: _BundleVerification | None = None,
    override: _OverrideDecision | None = None,
    rollout: _RolloutDecision | None = None,
):
    signing = _BundleSigningServiceStub(verification)
    overrides = _PolicyOverrideServiceStub(override)
    release = _ReleasePolicyServiceStub(rollout)
    enforcer = build_policy_enforcer(
        policy_bundle_signing_service=signing,
        policy_override_service=overrides,
        release_policy_service=release,
    )
    return enforcer, signing, overrides, release


def test_allow_signed_bundle_without_override():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        override=_OverrideDecision(
            allowed=False,
            verdict="none",
            active=False,
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="signed-value",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="execute",
        context={"risk": "low"},
    )

    assert result.allowed is True
    assert result.verdict == "allow"
    assert result.bundle_id == "bundle-001"
    assert result.runtime == "openclaw"
    assert result.override_active is False
    assert result.rollout_enabled is True
    assert "bundle:verified" in result.matched_rules
    assert "rollout:enabled" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(overrides.calls) == 1
    assert len(release.calls) == 1


def test_reject_invalid_signed_bundle_before_override():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=False,
            allowed=False,
            verdict="block",
            matched_rules=["signature_mismatch"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="bad-signature",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="claude",
        action="execute",
    )

    assert result.allowed is False
    assert result.verdict in {"block", "reject"}
    assert result.override_active is False
    assert result.rollout_enabled is False
    assert "signature_mismatch" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(overrides.calls) == 0
    assert len(release.calls) == 0


def test_active_allow_override_can_lift_policy_decision():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=False,
            verdict="review",
            matched_rules=["policy:review"],
        ),
        override=_OverrideDecision(
            allowed=True,
            verdict="allow",
            active=True,
            matched_rules=["override:allow"],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="guard",
        action="execute",
        context={"risk": "medium"},
    )

    assert result.allowed is True
    assert result.verdict == "allow"
    assert result.override_active is True
    assert "override:allow" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(overrides.calls) == 1
    assert len(release.calls) == 1


def test_active_block_override_forces_block():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        override=_OverrideDecision(
            allowed=False,
            verdict="block",
            active=True,
            matched_rules=["override:block"],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="execute",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.override_active is True
    assert "override:block" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(overrides.calls) == 1
    assert len(release.calls) == 0


def test_rollout_disabled_blocks_enforcement():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        override=_OverrideDecision(
            allowed=False,
            verdict="none",
            active=False,
        ),
        rollout=_RolloutDecision(
            enabled=False,
            allowed=False,
            verdict="block",
            matched_rules=["rollout:disabled"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="claude",
        action="execute",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.rollout_enabled is False
    assert "rollout:disabled" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(overrides.calls) == 1
    assert len(release.calls) == 1


def test_review_policy_decision_flows_through_when_no_override():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=False,
            verdict="review",
            matched_rules=["policy:review"],
        ),
        override=_OverrideDecision(
            allowed=False,
            verdict="none",
            active=False,
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="guard",
        action="execute",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert result.override_active is False
    assert result.rollout_enabled is True
    assert "policy:review" in result.matched_rules


def test_missing_bundle_blocks_early():
    enforcer, signing, overrides, release = _build()

    result = enforcer.evaluate(
        bundle=None,
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="execute",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert "missing_bundle" in result.matched_rules
    assert len(signing.calls) == 0
    assert len(overrides.calls) == 0
    assert len(release.calls) == 0


def test_missing_runtime_blocks_early():
    enforcer, signing, overrides, release = _build()

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="",
        action="execute",
    )

    assert result.allowed is False
    assert result.verdict == "block"
    assert "missing_runtime" in result.matched_rules
    assert len(signing.calls) == 0
    assert len(overrides.calls) == 0
    assert len(release.calls) == 0


def test_normalizes_runtime_before_downstream_calls():
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(valid=True, allowed=True, verdict="allow"),
        override=_OverrideDecision(active=False),
        rollout=_RolloutDecision(enabled=True, allowed=True, verdict="allow"),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="  Claude  ",
        action="execute",
    )

    assert result.runtime == "claude"
    assert signing.calls[0]["runtime"] == "claude"
    assert overrides.calls[0]["runtime"] == "claude"
    assert release.calls[0]["runtime"] == "claude"


def test_preserves_action_and_context_for_downstream_services():
    context = {"risk": "high", "tool": "bash"}
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(valid=True, allowed=True, verdict="allow"),
        override=_OverrideDecision(active=False),
        rollout=_RolloutDecision(enabled=True, allowed=True, verdict="allow"),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="tool.execute",
        context=context,
    )

    assert result.verdict == "allow"
    assert signing.calls[0]["bundle"]["bundle_id"] == "bundle-001"
    assert overrides.calls[0]["action"] == "tool.execute"
    assert overrides.calls[0]["context"] == context
    assert release.calls[0]["action"] == "tool.execute"
    assert release.calls[0]["context"] == context


def test_allow_helper_matches_enforcement_result():
    enforcer, _, _, _ = _build(
        verification=_BundleVerification(valid=True, allowed=True, verdict="allow"),
        override=_OverrideDecision(active=False),
        rollout=_RolloutDecision(enabled=True, allowed=True, verdict="allow"),
    )

    decision = enforcer.allow(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="execute",
    )

    assert decision is True


def test_allow_helper_false_when_blocked():
    enforcer, _, _, _ = _build(
        verification=_BundleVerification(valid=False, allowed=False, verdict="block"),
    )

    decision = enforcer.allow(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="bad",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="execute",
    )

    assert decision is False


def test_result_as_dict_contains_expected_shapes():
    enforcer, _, _, _ = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=True,
            verdict="allow",
            reasons=[{"source": "bundle", "label": "Verified", "details": "ok", "score": 5}],
            matched_rules=["bundle:verified"],
        ),
        override=_OverrideDecision(active=False),
        rollout=_RolloutDecision(enabled=True, allowed=True, verdict="allow"),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="guard",
        action="execute",
    )
    body = result.as_dict()

    assert body["allowed"] is True
    assert body["verdict"] == "allow"
    assert body["bundleid"] == "bundle-001"
    assert body["runtime"] == "guard"
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["reasons"], list)
    assert isinstance(body["bundleverification"], dict)
    assert isinstance(body["overrideevaluation"], dict)
    assert isinstance(body["rolloutevaluation"], dict)


def test_deduplicates_rules_and_reasons_across_stages():
    repeated_reason = {
        "source": "policy",
        "label": "Same",
        "details": "duplicate",
        "score": 10,
    }
    enforcer, _, _, _ = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=True,
            verdict="allow",
            reasons=[repeated_reason, repeated_reason],
            matched_rules=["dup-rule", "dup-rule"],
        ),
        override=_OverrideDecision(
            active=True,
            allowed=True,
            verdict="allow",
            reasons=[repeated_reason],
            matched_rules=["dup-rule"],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            reasons=[repeated_reason],
            matched_rules=["dup-rule"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime="openclaw",
        action="execute",
    )

    duplicates = [item for item in result.reasons if item["label"] == "Same" and item["details"] == "duplicate"]
    assert len(duplicates) == 1
    assert result.matched_rules.count("dup-rule") == 1


@pytest.mark.parametrize("runtime", ["openclaw", "claude", "guard", "future-runtime"])
def test_supports_cross_platform_runtime_names(runtime: str):
    enforcer, signing, overrides, release = _build(
        verification=_BundleVerification(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        override=_OverrideDecision(active=False),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
    )

    result = enforcer.evaluate(
        bundle={"bundle_id": "bundle-001", "version": "2026.04.25"},
        signature="good",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        runtime=runtime,
        action="execute",
    )

    assert result.allowed is True
    assert result.runtime == runtime
    assert signing.calls[0]["runtime"] == runtime
