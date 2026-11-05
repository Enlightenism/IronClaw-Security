from __future__ import annotations

from typing import Any

import pytest

from app.adapters.sandboxruntimeadapter import SandboxRuntimeAdapter


class _Decision:
    def __init__(self, allowed: bool) -> None:
        self.allowed = allowed
        self._payload = {
            "executionstate": "allowed" if allowed else "denied",
            "verdict": "allow" if allowed else "block",
            "reasons": [],
        }

    def as_dict(self) -> dict[str, Any]:
        return dict(self._payload)


class _Router:
    def __init__(self, allowed: bool) -> None:
        self._allowed = allowed

    def evaluate(self, *, request: Any) -> _Decision:
        return _Decision(self._allowed)

    def route(self, *, request: Any, executor: Any) -> Any:
        raise AssertionError("route must not be called without an executor")


def _unconfigured_reason_labels(payload: dict[str, Any]) -> list[str]:
    return [reason["label"] for reason in payload["reasons"]]


def test_execute_without_executor_denies_and_never_routes() -> None:
    adapter = SandboxRuntimeAdapter(router=_Router(allowed=True), executor=None)

    payload = adapter.execute(actiontype="shell", target="ls")

    assert payload["executionstate"] == "denied"
    assert payload["verdict"] == "block"
    assert payload["executed"] is False
    assert payload["result"] is None
    assert "No sandbox executor" in _unconfigured_reason_labels(payload)


@pytest.mark.parametrize("allowed", [True, False])
def test_execute_with_decision_without_executor_denies(allowed: bool) -> None:
    adapter = SandboxRuntimeAdapter(router=_Router(allowed=allowed), executor=None)

    payload = adapter.execute_with_decision(actiontype="shell", target="ls")

    assert payload["executed"] is False
    assert payload["verdict"] == "block"
    assert payload["result"] is None


def test_execute_with_decision_denied_by_policy_does_not_execute() -> None:
    adapter = SandboxRuntimeAdapter(router=_Router(allowed=False), executor=None)

    payload = adapter.execute_with_decision(actiontype="shell", target="rm -rf /")

    assert payload["executionstate"] == "denied"
    assert payload["verdict"] == "block"
    assert payload["executed"] is False


def test_evaluate_only_returns_router_decision_without_executor() -> None:
    adapter = SandboxRuntimeAdapter(router=_Router(allowed=True), executor=None)

    decision = adapter.evaluate_only(actiontype="shell", target="ls")

    assert decision["executionstate"] == "allowed"
    assert decision["verdict"] == "allow"
