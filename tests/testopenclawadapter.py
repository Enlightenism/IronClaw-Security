from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.adapters.openclawadapter import OpenClawAdapter


@dataclass(slots=True)
class _PolicyDecision:
    allowed: bool = True
    verdict: str = "allow"
    bundle_id: str = "bundle-001"
    version: str = "2026.04.25"
    runtime: str = "openclaw"
    override_active: bool = False
    rollout_enabled: bool = True
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "verdict": self.verdict,
            "bundleid": self.bundle_id,
            "version": self.version,
            "runtime": self.runtime,
            "overrideactive": self.override_active,
            "rolloutenabled": self.rollout_enabled,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


class _PolicyEnforcerStub:
    def __init__(self, decision: _PolicyDecision | None = None) -> None:
        self.decision = decision or _PolicyDecision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _PolicyDecision:
        self.calls.append(dict(kwargs))
        return self.decision

    def allow(self, **kwargs: Any) -> bool:
        self.calls.append(dict(kwargs))
        return self.decision.allowed


class _RuntimeClientStub:
    def __init__(self) -> None:
        self.execute_calls: list[dict[str, Any]] = []
        self.result: dict[str, Any] = {
            "status": "ok",
            "runtime": "openclaw",
            "output": {"message": "executed"},
        }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        self.execute_calls.append(dict(kwargs))
        return dict(self.result)


def _build_adapter(decision: _PolicyDecision | None = None):
    enforcer = _PolicyEnforcerStub(decision)
    runtime = _RuntimeClientStub()
    adapter = OpenClawAdapter(
        policy_enforcer=enforcer,
        runtime_client=runtime,
    )
    return adapter, enforcer, runtime


def _request_payload() -> dict[str, Any]:
    return {
        "bundle": {
            "bundle_id": "bundle-001",
            "version": "2026.04.25",
            "policy": {
                "default_verdict": "allow",
                "rules": [{"id": "safe-shell", "action": "allow"}],
            },
        },
        "signature": "signed-bundle",
        "secret": "ironclaw-secret",
        "manifest": {
            "bundleid": "bundle-001",
            "version": "2026.04.25",
            "algorithm": "hmac-sha256",
            "digest": "a" * 64,
        },
        "action": "execute",
        "prompt": "list safe files",
        "context": {
            "organization_id": "org-001",
            "risk": "low",
        },
    }


def test_allows_execution_when_policy_enforcer_allows():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified", "rollout:enabled"],
        )
    )

    result = adapter.execute(**_request_payload())

    assert result["allowed"] is True
    assert result["verdict"] == "allow"
    assert result["runtime"] == "openclaw"
    assert result["policy"]["bundleid"] == "bundle-001"
    assert result["policy"]["version"] == "2026.04.25"
    assert result["result"]["status"] == "ok"
    assert len(enforcer.calls) == 1
    assert len(runtime.execute_calls) == 1


def test_blocks_execution_when_policy_enforcer_blocks():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=False,
            verdict="block",
            matched_rules=["signature_mismatch"],
            reasons=[{"label": "Bad signature", "details": "Bundle verification failed"}],
        )
    )

    result = adapter.execute(**_request_payload())

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert result["runtime"] == "openclaw"
    assert "signature_mismatch" in result["policy"]["matchedrules"]
    assert result["result"] is None or result["result"].get("status") != "ok"
    assert len(enforcer.calls) == 1
    assert len(runtime.execute_calls) == 0


def test_review_verdict_prevents_runtime_execution():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=False,
            verdict="review",
            matched_rules=["policy:review"],
            reasons=[{"label": "Review", "details": "Needs analyst approval"}],
        )
    )

    result = adapter.execute(**_request_payload())

    assert result["allowed"] is False
    assert result["verdict"] == "review"
    assert result["policy"]["matchedrules"] == ["policy:review"]
    assert len(runtime.execute_calls) == 0


def test_passes_policy_material_to_enforcer():
    adapter, enforcer, runtime = _build_adapter()

    payload = _request_payload()
    adapter.execute(**payload)

    assert len(enforcer.calls) == 1
    call = enforcer.calls[0]
    assert call["bundle"]["bundle_id"] == "bundle-001"
    assert call["signature"] == "signed-bundle"
    assert call["secret"] == "ironclaw-secret"
    assert call["manifest"]["bundleid"] == "bundle-001"
    assert call["runtime"] == "openclaw"
    assert call["action"] == "execute"
    assert call["context"]["organization_id"] == "org-001"


def test_passes_prompt_and_context_to_runtime_client_after_allow():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        )
    )

    payload = _request_payload()
    adapter.execute(**payload)

    assert len(runtime.execute_calls) == 1
    call = runtime.execute_calls[0]
    assert call["prompt"] == "list safe files"
    assert call["context"]["organization_id"] == "org-001"


def test_missing_bundle_returns_block_without_runtime_call():
    adapter, enforcer, runtime = _build_adapter()

    payload = _request_payload()
    payload["bundle"] = None

    result = adapter.execute(**payload)

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert "missing_bundle" in result["policy"]["matchedrules"]
    assert len(enforcer.calls) == 0
    assert len(runtime.execute_calls) == 0


def test_missing_signature_returns_block_without_runtime_call():
    adapter, enforcer, runtime = _build_adapter()

    payload = _request_payload()
    payload["signature"] = ""

    result = adapter.execute(**payload)

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert "missing_signature" in result["policy"]["matchedrules"]
    assert len(enforcer.calls) == 0
    assert len(runtime.execute_calls) == 0


def test_missing_prompt_still_allows_when_action_only_policy_passes():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        )
    )

    payload = _request_payload()
    payload["prompt"] = ""

    result = adapter.execute(**payload)

    assert result["allowed"] is True
    assert result["verdict"] == "allow"
    assert len(runtime.execute_calls) == 1


def test_override_and_rollout_flags_are_exposed_in_response():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            override_active=True,
            rollout_enabled=False,
            matched_rules=["override:allow", "rollout:disabled-bypass"],
        )
    )

    result = adapter.execute(**_request_payload())

    assert result["policy"]["overrideactive"] is True
    assert result["policy"]["rolloutenabled"] is False
    assert "override:allow" in result["policy"]["matchedrules"]


def test_runtime_exception_is_captured_as_error_result():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        )
    )

    def _boom(**kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("runtime failure")

    runtime.execute = _boom  # type: ignore[method-assign]

    result = adapter.execute(**_request_payload())

    assert result["allowed"] is False
    assert result["verdict"] in {"error", "block"}
    assert "runtime_execution_error" in result["policy"]["matchedrules"]
    assert result["result"] is None or "error" in result


def test_allow_helper_matches_execution_decision():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
        )
    )

    allowed = adapter.allow(**_request_payload())

    assert allowed is True


def test_allow_helper_false_when_policy_rejects():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=False,
            verdict="block",
        )
    )

    allowed = adapter.allow(**_request_payload())

    assert allowed is False


def test_response_shape_is_json_friendly():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
            reasons=[{"label": "Verified", "details": "Signature valid"}],
        )
    )

    result = adapter.execute(**_request_payload())

    assert isinstance(result, dict)
    assert isinstance(result["policy"], dict)
    assert isinstance(result["policy"]["matchedrules"], list)
    assert isinstance(result["policy"]["reasons"], list)
    assert isinstance(result["result"], dict)


def test_reason_and_rule_deduplication_in_policy_response():
    adapter, enforcer, runtime = _build_adapter(
        _PolicyDecision(
            allowed=False,
            verdict="review",
            matched_rules=["dup-rule", "dup-rule"],
            reasons=[
                {"label": "Same", "details": "duplicate"},
                {"label": "Same", "details": "duplicate"},
            ],
        )
    )

    result = adapter.execute(**_request_payload())

    assert result["policy"]["matchedrules"].count("dup-rule") == 1
    duplicates = [
        item
        for item in result["policy"]["reasons"]
        if item["label"] == "Same" and item["details"] == "duplicate"
    ]
    assert len(duplicates) == 1


def test_runtime_name_is_normalized_to_openclaw():
    adapter, enforcer, runtime = _build_adapter()

    payload = _request_payload()
    payload["context"]["runtime_hint"] = "OpenClaw"

    result = adapter.execute(**payload)

    assert result["runtime"] == "openclaw"
    assert enforcer.calls[0]["runtime"] == "openclaw"