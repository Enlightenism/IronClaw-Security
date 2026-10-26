from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.services.guardsecuritybrain import build_guard_security_brain
from app.services.prompt_guard import PromptGuardResult


@dataclass(slots=True)
class _PolicyDecision:
    allowed: bool = True
    verdict: str = "allow"
    bundle_id: str = "bundle-001"
    version: str = "2026.04.25"
    runtime: str = "guard"
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


class _PromptGuardStub:
    def __init__(self, result: PromptGuardResult | None = None) -> None:
        self.enabled = True
        self.model_path = "models/prompt-guard-86m"
        self.threshold = 0.5
        self.classify_calls: list[str] = []
        self.result = result or PromptGuardResult(
            label="BENIGN",
            malicious_score=0.12,
            model_name="prompt-guard-86m",
        )

    def classify(self, text: str) -> PromptGuardResult | None:
        self.classify_calls.append(text)
        if not self.enabled or not text.strip():
            return None
        return self.result


def _build_brain(
    decision: _PolicyDecision | None = None,
    prompt_guard_result: PromptGuardResult | None = None,
):
    enforcer = _PolicyEnforcerStub(decision)
    client = _PromptGuardStub(prompt_guard_result)
    brain = build_guard_security_brain(
        policy_enforcer=enforcer,
        prompt_guard_client=client,
    )
    return brain, enforcer, client


def _request_payload() -> dict[str, Any]:
    return {
        "bundle": {
            "bundle_id": "bundle-001",
            "version": "2026.04.25",
            "policy": {
                "default_verdict": "allow",
                "rules": [{"id": "safe-guard", "action": "allow"}],
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
        "action": "chat.completions.create",
        "prompt": "summarize this repository safely",
        "context": {
            "organization_id": "org-001",
            "risk": "low",
            "model": "prompt-guard-86m-local",
        },
    }


def test_returns_prompt_guard_classification_when_policy_allows():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified", "rollout:enabled"],
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert result["allowed"] is True
    assert result["verdict"] == "allow"
    assert result["runtime"] == "guard"
    assert result["policy"]["bundleid"] == "bundle-001"
    assert result["policy"]["version"] == "2026.04.25"
    assert result["result"]["status"] == "classified"
    assert result["result"]["label"] == "BENIGN"
    assert len(enforcer.calls) == 1
    assert client.classify_calls == ["summarize this repository safely"]


def test_malicious_prompt_is_blocked_after_policy_allows():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(allowed=True, verdict="allow"),
        PromptGuardResult(
            label="MALICIOUS",
            malicious_score=0.97,
            model_name="prompt-guard-86m",
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert "prompt_guard:malicious" in result["policy"]["matchedrules"]
    assert result["result"]["label"] == "MALICIOUS"
    assert client.classify_calls == ["summarize this repository safely"]


def test_policy_block_prevents_prompt_guard_classification():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=False,
            verdict="block",
            matched_rules=["signature_mismatch"],
            reasons=[{"label": "Bad signature", "details": "Bundle verification failed"}],
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert result["runtime"] == "guard"
    assert "signature_mismatch" in result["policy"]["matchedrules"]
    assert result["result"] is None or result["result"].get("status") != "ok"
    assert len(enforcer.calls) == 1
    assert client.classify_calls == []


def test_review_verdict_prevents_prompt_guard_classification():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=False,
            verdict="review",
            matched_rules=["policy:review"],
            reasons=[{"label": "Review", "details": "Needs analyst approval"}],
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert result["allowed"] is False
    assert result["verdict"] == "review"
    assert result["policy"]["matchedrules"] == ["policy:review"]
    assert client.classify_calls == []


def test_passes_bundle_material_to_policy_enforcer():
    brain, enforcer, client = _build_brain()

    payload = _request_payload()
    brain.evaluate_request(**payload)

    assert len(enforcer.calls) == 1
    call = enforcer.calls[0]
    assert call["bundle"]["bundle_id"] == "bundle-001"
    assert call["signature"] == "signed-bundle"
    assert call["secret"] == "ironclaw-secret"
    assert call["manifest"]["bundleid"] == "bundle-001"
    assert call["runtime"] == "guard"
    assert call["action"] == "chat.completions.create"
    assert call["context"]["model"] == "prompt-guard-86m-local"


def test_classifies_prompt_after_policy_allows():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
    )

    payload = _request_payload()
    brain.evaluate_request(**payload)

    assert client.classify_calls == ["summarize this repository safely"]


def test_missing_bundle_returns_block_without_client_call():
    brain, enforcer, client = _build_brain()

    payload = _request_payload()
    payload["bundle"] = None

    result = brain.evaluate_request(**payload)

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert "missing_bundle" in result["policy"]["matchedrules"]
    assert len(enforcer.calls) == 0
    assert client.classify_calls == []


def test_missing_signature_returns_block_without_client_call():
    brain, enforcer, client = _build_brain()

    payload = _request_payload()
    payload["signature"] = ""

    result = brain.evaluate_request(**payload)

    assert result["allowed"] is False
    assert result["verdict"] == "block"
    assert "missing_signature" in result["policy"]["matchedrules"]
    assert len(enforcer.calls) == 0
    assert client.classify_calls == []


def test_empty_prompt_is_not_classified_when_policy_allows():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
    )

    payload = _request_payload()
    payload["prompt"] = ""

    result = brain.evaluate_request(**payload)

    assert result["allowed"] is True
    assert result["verdict"] == "allow"
    assert result["result"] == {
        "status": "not_classified",
        "reason": "empty_prompt",
        "model_name": "models/prompt-guard-86m",
    }
    assert client.classify_calls == []


def test_override_and_rollout_flags_are_exposed():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            override_active=True,
            rollout_enabled=False,
            matched_rules=["override:allow", "rollout:disabled-bypass"],
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert result["policy"]["overrideactive"] is True
    assert result["policy"]["rolloutenabled"] is False
    assert "override:allow" in result["policy"]["matchedrules"]


def test_prompt_guard_client_errors_are_not_hidden():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
    )

    def _boom(text: str) -> PromptGuardResult:
        raise RuntimeError("local model failure")

    client.classify = _boom  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="local model failure"):
        brain.evaluate_request(**_request_payload())


def test_allow_helper_matches_policy_decision():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
        ),
    )

    allowed = brain.allow_request(**_request_payload())

    assert allowed is True
    assert enforcer.calls[0]["runtime"] == "guard"


def test_allow_helper_false_when_policy_rejects():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=False,
            verdict="block",
        ),
    )

    allowed = brain.allow_request(**_request_payload())

    assert allowed is False


def test_response_shape_is_json_friendly():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
            reasons=[{"label": "Verified", "details": "Signature valid"}],
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert isinstance(result, dict)
    assert isinstance(result["policy"], dict)
    assert isinstance(result["policy"]["matchedrules"], list)
    assert isinstance(result["policy"]["reasons"], list)
    assert isinstance(result["result"], dict)
    assert result["result"]["status"] == "classified"
    assert set(result["result"]) == {"status", "label", "malicious_score", "model_name"}


def test_reason_and_rule_deduplication_in_policy_response():
    brain, enforcer, client = _build_brain(
        _PolicyDecision(
            allowed=False,
            verdict="review",
            matched_rules=["dup-rule", "dup-rule"],
            reasons=[
                {"label": "Same", "details": "duplicate"},
                {"label": "Same", "details": "duplicate"},
            ],
        ),
    )

    result = brain.evaluate_request(**_request_payload())

    assert result["policy"]["matchedrules"].count("dup-rule") == 1
    duplicates = [item for item in result["policy"]["reasons"] if item["label"] == "Same" and item["details"] == "duplicate"]
    assert len(duplicates) == 1


def test_runtime_name_is_guard():
    brain, enforcer, client = _build_brain()

    result = brain.evaluate_request(**_request_payload())

    assert result["runtime"] == "guard"
    assert enforcer.calls[0]["runtime"] == "guard"
