from __future__ import annotations

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.services.attack_correlation import (
    build_correlation_event,
    correlate_attack_events,
    summarize_correlation_summary,
)
from app.services.attackcorrelation import (
    AttackCorrelationService as ParallelAttackCorrelationService,
)


def test_build_correlation_event_normalizes_and_bounds_score():
    event = build_correlation_event(
        event_id=" evt-1 ",
        action_type=" toolcall ",
        target=" workspace://agent ",
        verdict="block",
        risk_score=120,
    )

    assert event.event_id == "evt-1"
    assert event.action_type == "toolcall"
    assert event.target == "workspace://agent"
    assert event.verdict == "block"
    assert event.risk_score == 100


def test_correlate_attack_events_returns_allow_for_low_signal_sequence():
    events = [
        build_correlation_event(
            event_id="evt-1",
            action_type="filewrite",
            target="workspace://notes.txt",
            verdict="allow",
            risk_score=10,
        ),
        build_correlation_event(
            event_id="evt-2",
            action_type="fileread",
            target="workspace://todo.txt",
            verdict="allow",
            risk_score=15,
        ),
    ]

    summary = correlate_attack_events(events)

    assert summary.verdict == "allow"
    assert summary.escalation_score <= RISK_THRESHOLD_ALLOW_MAX
    assert summary.total_events == 2


def test_correlate_attack_events_blocks_repeated_patterns():
    events = [
        build_correlation_event(
            event_id="evt-1",
            action_type="toolcall",
            target="workspace://agent",
            verdict="block",
            risk_score=45,
        ),
        build_correlation_event(
            event_id="evt-2",
            action_type="toolcall",
            target="workspace://agent",
            verdict="block",
            risk_score=50,
        ),
        build_correlation_event(
            event_id="evt-3",
            action_type="networkrequest",
            target="https://example.test",
            verdict="allow",
            risk_score=20,
        ),
    ]

    summary = correlate_attack_events(events)

    assert summary.verdict == "block"
    assert "workspace://agent" in summary.repeated_targets
    assert "toolcall" in summary.repeated_action_types
    assert len(summary.reasons) >= 1


def test_correlate_attack_events_blocks_high_risk_campaign():
    events = [
        build_correlation_event(
            event_id="evt-1",
            action_type="shellcommand",
            target="https://evil.example/1",
            verdict="block",
            risk_score=95,
        ),
        build_correlation_event(
            event_id="evt-2",
            action_type="shellcommand",
            target="https://evil.example/1",
            verdict="block",
            risk_score=90,
        ),
        build_correlation_event(
            event_id="evt-3",
            action_type="toolcall",
            target="workspace://agent",
            verdict="block",
            risk_score=85,
        ),
        build_correlation_event(
            event_id="evt-4",
            action_type="toolcall",
            target="workspace://agent",
            verdict="block",
            risk_score=70,
        ),
        build_correlation_event(
            event_id="evt-5",
            action_type="networkrequest",
            target="https://evil.example/2",
            verdict="block",
            risk_score=75,
        ),
    ]

    summary = correlate_attack_events(events)

    assert summary.verdict == "block"
    assert summary.escalation_score >= RISK_THRESHOLD_BLOCK_MIN
    assert summary.high_risk_events >= 4


def test_correlate_attack_events_blocks_a_low_risk_match():
    event = build_correlation_event(
        event_id="evt-low-match",
        action_type="toolcall",
        target="workspace://agent",
        verdict="block",
        risk_score=20,
    )

    summary = correlate_attack_events([event])

    assert summary.verdict == "block"
    assert summary.reasons
    assert summary.escalation_score >= RISK_THRESHOLD_BLOCK_MIN


def test_summarize_correlation_summary_returns_expected_shape():
    events = [
        build_correlation_event(
            event_id="evt-1",
            action_type="toolcall",
            target="workspace://agent",
            verdict="block",
            risk_score=45,
        ),
    ]

    summary = correlate_attack_events(events)
    payload = summarize_correlation_summary(summary)

    assert payload["verdict"] in {"allow", "block"}
    assert payload["total_events"] == 1
    assert "reason_count" in payload


def test_parallel_correlation_emits_only_block_actions_for_suspicious_signal():
    result = ParallelAttackCorrelationService().correlate(
        [
            {
                "signal_id": "sig-block",
                "signal_type": "prompt_injection",
                "source": "prompt_guard",
                "severity": "medium",
                "summary": "Suspicious prompt signal",
                "score": RISK_THRESHOLD_ALLOW_MAX + 1,
            },
        ],
        session_id="sess-block",
    )

    escalation = result["escalations"]

    assert escalation["block_actions"] == 1
    assert escalation["review_actions"] == 0
    assert escalation["quarantine_actions"] == 0
    assert [item["action_type"] for item in escalation["items"]] == ["block"]
    assert escalation["items"][0]["risk_score"] >= RISK_THRESHOLD_BLOCK_MIN
    assert result["summary"]["overall_risk_score"] >= RISK_THRESHOLD_BLOCK_MIN
