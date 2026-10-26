from __future__ import annotations

import pytest

from app.services.guard_security_brain import GuardSecurityDecision
from app.services.verdict_enforcer import EnforcedVerdict, VerdictType, enforce_verdict


def _guard_decision(
    verdict: VerdictType,
    *,
    risk_score: int = 95,
) -> GuardSecurityDecision:
    return GuardSecurityDecision(
        mode="enforce",
        verdict=verdict,
        risk_score=risk_score,
        summary="Prompt Guard classified the request as malicious.",
        reasoning=["A malicious prompt was detected."],
        signals=["prompt-guard-malicious"],
        model_name="prompt-guard-86m-local",
        decided_at="2026-10-25T20:00:00+00:00",
        confidence=0.97,
        latency_ms=12.5,
    )


def _enforce(
    *,
    verdict: VerdictType = "allow",
    risk_score: int = 25,
    guard_decision: GuardSecurityDecision | None = None,
    reasons: list[dict[str, object]] | None = None,
) -> EnforcedVerdict:
    return enforce_verdict(
        action_type="toolcall",
        target="workspace://agent",
        content="request content",
        verdict=verdict,
        summary="Baseline decision.",
        risk_score=risk_score,
        should_halt=verdict in ("block", "quarantine"),
        should_warn=verdict in ("warn", "quarantine"),
        reasons=reasons,
        guard_decision=guard_decision,
    )


def test_missing_guard_decision_returns_empty_guard_telemetry() -> None:
    result = _enforce()

    assert result["verdict"] == "allow"
    assert result["should_halt"] is False
    assert result["should_warn"] is False
    assert result["guard_verdict"] is None
    assert result["guard_risk_score"] is None
    assert result["guard_confidence"] is None
    assert result["guard_latency_ms"] is None
    assert result["guard_model_name"] is None
    assert result["guard_signals"] == []
    assert result["guard_summary"] is None
    assert result["guard_decided_at"] is None


def test_guard_telemetry_is_propagated_and_harder_verdict_escalates() -> None:
    guard_decision = _guard_decision("block")
    baseline_reason = {
        "source": "policy",
        "label": "Policy review",
        "details": "The baseline requested review.",
    }
    reasons = [baseline_reason]

    result = _enforce(
        verdict="warn",
        risk_score=45,
        guard_decision=guard_decision,
        reasons=reasons,
    )

    assert result["verdict"] == "block"
    assert result["risk_score"] == 45
    assert result["should_halt"] is True
    assert result["should_warn"] is False
    assert result["guard_verdict"] == "block"
    assert result["guard_risk_score"] == 95
    assert result["guard_confidence"] == pytest.approx(0.97)
    assert result["guard_latency_ms"] == pytest.approx(12.5)
    assert result["guard_model_name"] == "prompt-guard-86m-local"
    assert result["guard_signals"] == ["prompt-guard-malicious"]
    assert result["guard_summary"] == guard_decision.summary
    assert result["guard_decided_at"] == guard_decision.decided_at
    assert reasons == [baseline_reason]
    assert result["reasons"][0] == baseline_reason

    escalation_reason = result["reasons"][1]
    assert escalation_reason["source"] == "ai"
    assert escalation_reason["label"] == "Guard security brain escalation"
    assert escalation_reason["details"] == guard_decision.summary
    assert escalation_reason["score"] == pytest.approx(0.95)


@pytest.mark.parametrize(
    ("baseline_verdict", "guard_verdict"),
    [
        ("block", "allow"),
        ("quarantine", "warn"),
        ("warn", "allow"),
        ("allow", "allow"),
    ],
)
def test_guard_verdict_never_downgrades_baseline(
    baseline_verdict: VerdictType,
    guard_verdict: VerdictType,
) -> None:
    result = _enforce(
        verdict=baseline_verdict,
        guard_decision=_guard_decision(guard_verdict, risk_score=25),
    )

    assert result["verdict"] == baseline_verdict
    assert result["reasons"] == []


def test_quarantine_verdict_sets_both_halt_and_warn_flags() -> None:
    result = _enforce(
        guard_decision=_guard_decision("quarantine", risk_score=75),
    )

    assert result["verdict"] == "quarantine"
    assert result["should_halt"] is True
    assert result["should_warn"] is True
