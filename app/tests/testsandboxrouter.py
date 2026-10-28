from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from app.config import RISK_THRESHOLD_BLOCK_MIN
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

    def evaluate(self, **kwargs: Any) -> _Policy:
        return self.policy


def _build_router(command_policy: _Policy) -> SandboxRouter:
    return SandboxRouter(
        command_supervisor=_PolicyGuard(command_policy),
        network_guard=_PolicyGuard(_Policy()),
        file_return_guard=_PolicyGuard(_Policy()),
    )


def _request() -> SandboxExecutionRequest:
    return SandboxExecutionRequest(
        actiontype="sandbox_route",
        target="sandbox",
        command="python report.py",
    )


def test_sandbox_router_allows_a_safe_command() -> None:
    router = _build_router(
        _Policy(
            risk_delta=4,
            matched_rules=["execution_boundary"],
        ),
    )

    decision = router.evaluate(request=_request())

    assert decision.verdict == "allow"
    assert decision.allowed is True
    assert decision.shouldblock is False
    assert decision.shouldquarantine is False


def test_sandbox_router_blocks_low_severity_matches() -> None:
    router = _build_router(
        _Policy(matched_rules=["low_severity_pattern"]),
    )

    decision = router.evaluate(request=_request())

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.shouldblock is True
    assert decision.shouldquarantine is False
    assert decision.riskdelta >= RISK_THRESHOLD_BLOCK_MIN


@pytest.mark.parametrize(
    "policy",
    [
        pytest.param(_Policy(verdict="warn", should_warn=True), id="legacy-warning"),
        pytest.param(
            _Policy(verdict="quarantine", should_quarantine=True),
            id="legacy-quarantine",
        ),
        pytest.param(_Policy(verdict="review", should_review=True), id="review"),
    ],
)
def test_sandbox_router_fails_closed_for_non_allow_policies(
    policy: _Policy,
) -> None:
    router = _build_router(policy)

    decision = router.evaluate(request=_request())

    assert decision.verdict == "block"
    assert decision.allowed is False
    assert decision.shouldblock is True
    assert decision.shouldquarantine is False
    assert decision.riskdelta >= RISK_THRESHOLD_BLOCK_MIN
