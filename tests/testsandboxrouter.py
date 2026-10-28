from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.runtime.sandboxrouter import SandboxExecutionRequest, SandboxRouter


@dataclass(slots=True)
class _Policy:
    verdict: str = "allow"
    allowed: bool = True
    should_review: bool = False
    should_warn: bool = False
    should_block: bool = False
    should_quarantine: bool = False
    risk_delta: int = 0
    reasons: list[dict[str, Any]] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldwarn": self.should_warn,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": self.risk_delta,
            "reasons": list(self.reasons),
            "matchedrules": list(self.matched_rules),
        }


class _PolicyGuard:
    def __init__(self, policy: _Policy) -> None:
        self.policy = policy
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Policy:
        self.calls.append(dict(kwargs))
        return self.policy


def _build_router(
    *,
    command_policy: _Policy | None = None,
    network_policy: _Policy | None = None,
    artifact_policy: _Policy | None = None,
    executor: Callable[..., Any] | None = None,
) -> tuple[SandboxRouter, _PolicyGuard, _PolicyGuard, _PolicyGuard]:
    command_guard = _PolicyGuard(command_policy or _Policy())
    network_guard = _PolicyGuard(network_policy or _Policy())
    artifact_guard = _PolicyGuard(artifact_policy or _Policy())
    router = SandboxRouter(
        command_supervisor=command_guard,
        network_guard=network_guard,
        file_return_guard=artifact_guard,
        default_executor=executor,
    )
    return router, command_guard, network_guard, artifact_guard


def _request(**kwargs: Any) -> SandboxExecutionRequest:
    return SandboxExecutionRequest(
        actiontype="execute",
        target="sandbox",
        **kwargs,
    )


def test_safe_request_allows_and_preserves_executor_payload() -> None:
    calls: list[dict[str, Any]] = []

    def executor(**kwargs: Any) -> dict[str, bool]:
        calls.append(dict(kwargs))
        return {"ok": True}

    router, _, network_guard, artifact_guard = _build_router(
        command_policy=_Policy(
            risk_delta=5,
            matched_rules=["execution_boundary"],
        ),
        network_policy=_Policy(matched_rules=["allowed_host:example.com"]),
        executor=executor,
    )
    request = _request(
        command="echo safe",
        network_url="https://example.com/status",
        network_method="POST",
        artifact_paths=["output/report.txt"],
        content="safe output",
        timeout_seconds=10,
        metadata={"trace_id": "trace-1"},
    )

    result = router.route(request=request)

    assert result.verdict == "allow"
    assert result.executed is True
    assert result.result == {"ok": True}
    assert result.decision["shouldquarantine"] is False
    assert len(calls) == 1
    assert calls[0]["command"] == "echo safe"
    assert calls[0]["network_method"] == "POST"
    assert calls[0]["artifact_paths"] == ["output/report.txt"]
    assert calls[0]["metadata"]["trace_id"] == "trace-1"
    assert len(network_guard.calls) == 1
    assert len(artifact_guard.calls) == 1


def test_low_severity_match_blocks_and_floors_risk() -> None:
    calls: list[dict[str, Any]] = []
    router, _, _, _ = _build_router(
        command_policy=_Policy(
            matched_rules=["low_severity_pattern"],
        ),
        executor=lambda **kwargs: calls.append(dict(kwargs)),
    )

    result = router.route(request=_request(command="echo suspicious"))

    assert result.verdict == "block"
    assert result.executed is False
    assert result.decision["shouldblock"] is True
    assert result.decision["shouldquarantine"] is False
    assert result.decision["riskdelta"] >= RISK_THRESHOLD_BLOCK_MIN
    assert calls == []


@pytest.mark.parametrize(
    ("policy", "expected_review"),
    [
        pytest.param(
            _Policy(verdict="warn", should_warn=True, should_review=True),
            True,
            id="legacy-warning",
        ),
        pytest.param(
            _Policy(verdict="quarantine", should_quarantine=True),
            False,
            id="legacy-quarantine",
        ),
        pytest.param(_Policy(verdict="invalid"), False, id="invalid-verdict"),
    ],
)
def test_non_allow_policy_outcomes_fail_closed(
    policy: _Policy,
    expected_review: bool,
) -> None:
    router, _, _, _ = _build_router(command_policy=policy)

    decision = router.evaluate(request=_request(command="echo checked"))

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.shouldblock is True
    assert decision.shouldreview is expected_review
    assert decision.shouldquarantine is False
    assert decision.riskdelta >= RISK_THRESHOLD_BLOCK_MIN


def test_review_flag_is_lifecycle_metadata_but_blocks_execution() -> None:
    router, _, _, _ = _build_router(
        command_policy=_Policy(should_review=True),
    )

    decision = router.evaluate(request=_request(command="echo reviewed"))

    assert decision.verdict == "block"
    assert decision.shouldreview is True
    assert decision.executionstate == "queuedforreview"
    assert decision.shouldquarantine is False


def test_risk_above_allow_limit_blocks_and_floors_risk() -> None:
    router, _, _, _ = _build_router(
        command_policy=_Policy(risk_delta=RISK_THRESHOLD_ALLOW_MAX + 1),
    )

    decision = router.evaluate(request=_request(command="echo risky"))

    assert decision.verdict == "block"
    assert decision.riskdelta >= RISK_THRESHOLD_BLOCK_MIN


def test_out_of_sandbox_environment_blocks() -> None:
    router, _, _, _ = _build_router()

    decision = router.evaluate(
        request=_request(command="echo risky", environment_scope="host"),
    )

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.riskdelta >= RISK_THRESHOLD_BLOCK_MIN
