from __future__ import annotations

from pydantic import ValidationError
import pytest

from app.api.prompt_guard import GuardedTextResponse, PromptGuardResponse
from app.services import guard, prompt_service


def _scan_result(
    *,
    verdict: str = "allow",
    risk_score: int = 0,
    matched_patterns: list[str] | None = None,
    failed_checks: list[str] | None = None,
    quarantine_reason: str | None = None,
    summary: str = "No risky patterns detected.",
) -> dict:
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "matched_patterns": matched_patterns or [],
        "failed_checks": failed_checks or [],
        "quarantine_reason": quarantine_reason,
        "summary": summary,
        "scan_id": "scan-test-001",
    }


def _prompt_decision(verdict: str) -> dict:
    return {
        "context_type": "user_prompt",
        "verdict": verdict,
        "scan_id": "scan-test-001",
        "summary": "Test decision.",
        "risk_score": 0,
        "matched_patterns": [],
    }


@pytest.mark.parametrize(
    "context_type",
    ["user_prompt", "retrieved_doc", "tool_output", "model_output"],
)
def test_guard_allows_clean_scan_for_any_context(monkeypatch, context_type):
    risk_score = max(0, min(guard.RISK_THRESHOLD_ALLOW_MAX, 100))
    scan_result = _scan_result(risk_score=risk_score)
    monkeypatch.setattr(guard, "perform_scan", lambda *_args: scan_result)

    decision = guard.guard_text(context_type, "A harmless prompt.")

    assert decision["verdict"] == "allow"
    assert decision["risk_score"] == risk_score
    assert decision["matched_patterns"] == []


def test_guard_blocks_any_matched_pattern_and_floors_risk(monkeypatch):
    scan_result = _scan_result(
        matched_patterns=["low_severity_rule"],
        risk_score=1,
    )
    monkeypatch.setattr(guard, "perform_scan", lambda *_args: scan_result)

    decision = guard.guard_text("user_prompt", "A matched low-severity pattern.")

    assert decision["verdict"] == "block"
    assert decision["matched_patterns"] == ["low_severity_rule"]
    assert decision["risk_score"] >= guard.RISK_THRESHOLD_BLOCK_MIN


def test_guard_blocks_prompt_guard_failure_with_reason(monkeypatch):
    scan_result = _scan_result(
        verdict="block",
        failed_checks=["prompt_guard_unavailable"],
        quarantine_reason="prompt_guard_unavailable",
        summary="Scan failed; request blocked.",
    )
    monkeypatch.setattr(guard, "perform_scan", lambda *_args: scan_result)

    decision = guard.guard_text("user_prompt", "A harmless-looking prompt.")

    assert decision["verdict"] == "block"
    assert "prompt_guard_unavailable" in decision["summary"]
    assert decision["risk_score"] >= guard.RISK_THRESHOLD_BLOCK_MIN


def test_guard_blocks_scores_above_configured_allow_ceiling(monkeypatch):
    allow_max = min(guard.RISK_THRESHOLD_ALLOW_MAX, 99)
    monkeypatch.setattr(guard, "RISK_THRESHOLD_ALLOW_MAX", allow_max)
    scan_result = _scan_result(risk_score=allow_max + 1)
    monkeypatch.setattr(guard, "perform_scan", lambda *_args: scan_result)

    decision = guard.guard_text("user_prompt", "A clean-looking prompt.")

    assert decision["verdict"] == "block"
    assert "configured allow threshold" in decision["summary"]
    assert decision["risk_score"] >= guard.RISK_THRESHOLD_BLOCK_MIN


def test_guard_blocks_when_scanner_raises(monkeypatch):
    def fail_scan(*_args):
        raise RuntimeError("scanner failed")

    monkeypatch.setattr(guard, "perform_scan", fail_scan)

    decision = guard.guard_text("user_prompt", "A prompt.")

    assert decision["verdict"] == "block"
    assert "scan_unavailable" in decision["summary"]
    assert decision["risk_score"] >= guard.RISK_THRESHOLD_BLOCK_MIN


@pytest.mark.parametrize("legacy_verdict", ["warn", "quarantine"])
def test_guard_blocks_legacy_verdicts(monkeypatch, legacy_verdict):
    scan_result = _scan_result(verdict=legacy_verdict)
    monkeypatch.setattr(guard, "perform_scan", lambda *_args: scan_result)

    decision = guard.guard_text("user_prompt", "A prompt.")

    assert decision["verdict"] == "block"
    assert decision["risk_score"] >= guard.RISK_THRESHOLD_BLOCK_MIN


@pytest.mark.parametrize("verdict", ["allow", "block"])
def test_prompt_service_only_emits_allow_or_block_and_never_warns(monkeypatch, verdict):
    monkeypatch.setattr(
        prompt_service,
        "guard_text",
        lambda *_args: _prompt_decision(verdict),
    )

    result = prompt_service.analyze_text("retrieved_doc", "Test text.")

    assert result["verdict"] == verdict
    assert result["should_halt"] is (verdict == "block")
    assert result["should_warn"] is False


def test_prompt_bundle_aggregates_block_without_warning(monkeypatch):
    monkeypatch.setattr(
        prompt_service,
        "guard_text",
        lambda context_type, _text: _prompt_decision("block" if context_type == "tool_output" else "allow"),
    )

    bundle = prompt_service.analyze_prompt_bundle(
        user_prompt="Safe user prompt.",
        tool_output="Blocked tool output.",
    )

    tool_output = bundle["tool_output"]
    assert tool_output is not None
    assert bundle["highest_verdict"] == "block"
    assert bundle["should_halt"] is True
    assert bundle["should_warn"] is False
    assert tool_output["should_halt"] is True
    assert tool_output["should_warn"] is False


def test_empty_prompt_bundle_allows_without_warning():
    bundle = prompt_service.analyze_prompt_bundle()

    assert bundle["highest_verdict"] == "allow"
    assert bundle["should_halt"] is False
    assert bundle["should_warn"] is False


@pytest.mark.parametrize("legacy_verdict", ["warn", "quarantine"])
def test_prompt_guard_response_models_reject_legacy_verdicts(legacy_verdict):
    with pytest.raises(ValidationError):
        GuardedTextResponse(
            context_type="user_prompt",
            verdict=legacy_verdict,
            scan_id=None,
            summary="Legacy verdict.",
            risk_score=0,
            matched_patterns=[],
            original_text="prompt",
            effective_text="prompt",
            should_halt=False,
            should_warn=False,
        )

    with pytest.raises(ValidationError):
        PromptGuardResponse(
            user_prompt=None,
            retrieved_doc=None,
            tool_output=None,
            model_output=None,
            highest_verdict=legacy_verdict,
            should_halt=False,
            should_warn=False,
        )


def test_prompt_guard_response_models_reject_warning_flags():
    with pytest.raises(ValidationError):
        GuardedTextResponse(
            context_type="user_prompt",
            verdict="block",
            scan_id=None,
            summary="Blocked.",
            risk_score=70,
            matched_patterns=[],
            original_text="prompt",
            effective_text="prompt",
            should_halt=True,
            should_warn=True,
        )

    with pytest.raises(ValidationError):
        PromptGuardResponse(
            user_prompt=None,
            retrieved_doc=None,
            tool_output=None,
            model_output=None,
            highest_verdict="block",
            should_halt=True,
            should_warn=True,
        )
