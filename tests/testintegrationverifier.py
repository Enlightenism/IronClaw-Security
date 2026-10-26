from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.services.integrationverifier import build_integration_verifier


@dataclass(slots=True)
class _VerificationResult:
    valid: bool = True
    allowed: bool = True
    verdict: str = "allow"
    bundle_id: str = "bundle-001"
    version: str = "2026.04.25"
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "bundleid": self.bundle_id,
            "version": self.version,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class _RolloutDecision:
    enabled: bool = True
    allowed: bool = True
    verdict: str = "allow"
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class _AdapterProbeResult:
    ok: bool = True
    installed: bool = True
    runtime: str = "openclaw"
    adapter: str = "openclaw"
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None
    capabilities: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []
        if self.capabilities is None:
            self.capabilities = {
                "supports_policy_bundles": True,
                "supports_overrides": True,
                "supports_rollout_controls": True,
            }

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "installed": self.installed,
            "runtime": self.runtime,
            "adapter": self.adapter,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "capabilities": dict(self.capabilities),
        }


class _BundleSigningServiceStub:
    def __init__(self, result: _VerificationResult | None = None) -> None:
        self.result = result or _VerificationResult()
        self.calls: list[dict[str, Any]] = []

    def verify_bundle(self, **kwargs: Any) -> _VerificationResult:
        self.calls.append(dict(kwargs))
        return self.result


class _ReleasePolicyServiceStub:
    def __init__(self, result: _RolloutDecision | None = None) -> None:
        self.result = result or _RolloutDecision()
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _RolloutDecision:
        self.calls.append(dict(kwargs))
        return self.result


class _AdapterRegistryStub:
    def __init__(self, result: _AdapterProbeResult | None = None) -> None:
        self.result = result or _AdapterProbeResult()
        self.calls: list[dict[str, Any]] = []

    def verify_runtime(self, **kwargs: Any) -> _AdapterProbeResult:
        self.calls.append(dict(kwargs))
        return self.result


def _build(
    *,
    verification: _VerificationResult | None = None,
    rollout: _RolloutDecision | None = None,
    adapter_probe: _AdapterProbeResult | None = None,
):
    signing = _BundleSigningServiceStub(verification)
    release = _ReleasePolicyServiceStub(rollout)
    registry = _AdapterRegistryStub(adapter_probe)
    verifier = build_integration_verifier(
        policy_bundle_signing_service=signing,
        release_policy_service=release,
        adapter_registry=registry,
    )
    return verifier, signing, release, registry


def _bundle() -> dict[str, Any]:
    return {
        "bundle_id": "bundle-001",
        "version": "2026.04.25",
        "policy": {
            "default_verdict": "allow",
            "rules": [{"id": "safe-rule", "action": "allow"}],
        },
        "metadata": {"issuer": "ironclaw"},
    }


def test_verifier_accepts_valid_bundle_and_supported_runtime():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
        adapter_probe=_AdapterProbeResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            matched_rules=["adapter:ready"],
        ),
    )

    result = verifier.verify(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={
            "bundleid": "bundle-001",
            "version": "2026.04.25",
            "algorithm": "hmac-sha256",
            "digest": "a" * 64,
        },
        action="execute",
        context={"organization_id": "org-001"},
    )

    assert result.ok is True
    assert result.allowed is True
    assert result.runtime == "openclaw"
    assert result.verdict == "allow"
    assert "bundle:verified" in result.matched_rules
    assert "rollout:enabled" in result.matched_rules
    assert "adapter:ready" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(release.calls) == 1
    assert len(registry.calls) == 1


def test_verifier_rejects_invalid_bundle_signature():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(
            valid=False,
            allowed=False,
            verdict="block",
            matched_rules=["signature_mismatch"],
            reasons=[{"label": "Bad signature", "details": "Bundle verification failed"}],
        ),
    )

    result = verifier.verify(
        runtime="claude",
        bundle=_bundle(),
        signature="bad-signature",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.ok is False
    assert result.allowed is False
    assert result.verdict in {"block", "reject"}
    assert "signature_mismatch" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(release.calls) == 0
    assert len(registry.calls) == 0


def test_verifier_rejects_disabled_rollout():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        rollout=_RolloutDecision(
            enabled=False,
            allowed=False,
            verdict="block",
            matched_rules=["rollout:disabled"],
            reasons=[{"label": "Disabled", "details": "Rollout disabled"}],
        ),
    )

    result = verifier.verify(
        runtime="guard",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.ok is False
    assert result.allowed is False
    assert result.verdict == "block"
    assert "rollout:disabled" in result.matched_rules
    assert len(signing.calls) == 1
    assert len(release.calls) == 1
    assert len(registry.calls) == 0


def test_verifier_rejects_missing_runtime_adapter():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
        adapter_probe=_AdapterProbeResult(
            ok=False,
            installed=False,
            runtime="future-runtime",
            adapter="future-runtime",
            matched_rules=["adapter:not-installed"],
            reasons=[{"label": "Missing adapter", "details": "Runtime adapter unavailable"}],
        ),
    )

    result = verifier.verify(
        runtime="future-runtime",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.ok is False
    assert result.allowed is False
    assert result.verdict in {"block", "reject"}
    assert "adapter:not-installed" in result.matched_rules
    assert len(registry.calls) == 1


def test_verifier_passes_runtime_action_and_context_to_dependencies():
    verifier, signing, release, registry = _build()

    result = verifier.verify(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="tool.execute",
        context={"organization_id": "org-001", "risk": "low"},
    )

    assert result.ok is True
    assert signing.calls[0]["bundle"]["bundle_id"] == "bundle-001"
    assert release.calls[0]["runtime"] == "openclaw"
    assert release.calls[0]["action"] == "tool.execute"
    assert release.calls[0]["context"]["organization_id"] == "org-001"
    assert registry.calls[0]["runtime"] == "openclaw"


def test_missing_bundle_is_rejected_early():
    verifier, signing, release, registry = _build()

    result = verifier.verify(
        runtime="openclaw",
        bundle=None,
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.ok is False
    assert result.allowed is False
    assert result.verdict == "block"
    assert "missing_bundle" in result.matched_rules
    assert len(signing.calls) == 0
    assert len(release.calls) == 0
    assert len(registry.calls) == 0


def test_missing_signature_is_rejected_early():
    verifier, signing, release, registry = _build()

    result = verifier.verify(
        runtime="openclaw",
        bundle=_bundle(),
        signature="",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.ok is False
    assert result.allowed is False
    assert result.verdict == "block"
    assert "missing_signature" in result.matched_rules
    assert len(signing.calls) == 0


def test_missing_runtime_is_rejected_early():
    verifier, signing, release, registry = _build()

    result = verifier.verify(
        runtime="",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.ok is False
    assert result.allowed is False
    assert result.verdict == "block"
    assert "missing_runtime" in result.matched_rules
    assert len(signing.calls) == 0


def test_verifier_supports_cross_platform_runtimes():
    for runtime_name in ["openclaw", "claude", "guard", "future-runtime"]:
        verifier, signing, release, registry = _build(
            adapter_probe=_AdapterProbeResult(
                ok=True,
                installed=True,
                runtime=runtime_name,
                adapter=runtime_name,
                matched_rules=[f"adapter:{runtime_name}:ready"],
            ),
        )

        result = verifier.verify(
            runtime=runtime_name,
            bundle=_bundle(),
            signature="signed-bundle",
            secret="ironclaw-secret",
            manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
            action="execute",
        )

        assert result.ok is True
        assert result.runtime == runtime_name
        assert registry.calls[0]["runtime"] == runtime_name


def test_json_shape_contains_component_sections():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["bundle:verified"],
            reasons=[{"label": "Verified", "details": "Signature valid"}],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["rollout:enabled"],
        ),
        adapter_probe=_AdapterProbeResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            matched_rules=["adapter:ready"],
        ),
    )

    result = verifier.verify(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )
    body = result.as_dict()

    assert body["ok"] is True
    assert body["allowed"] is True
    assert body["runtime"] == "openclaw"
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["reasons"], list)
    assert isinstance(body["bundleverification"], dict)
    assert isinstance(body["rolloutevaluation"], dict)
    assert isinstance(body["adapterverification"], dict)


def test_rules_and_reasons_are_deduplicated_across_checks():
    repeated_reason = {"label": "Same", "details": "duplicate", "score": 10}
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(
            valid=True,
            allowed=True,
            verdict="allow",
            matched_rules=["dup-rule", "dup-rule"],
            reasons=[repeated_reason, repeated_reason],
        ),
        rollout=_RolloutDecision(
            enabled=True,
            allowed=True,
            verdict="allow",
            matched_rules=["dup-rule"],
            reasons=[repeated_reason],
        ),
        adapter_probe=_AdapterProbeResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            matched_rules=["dup-rule"],
            reasons=[repeated_reason],
        ),
    )

    result = verifier.verify(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert result.matched_rules.count("dup-rule") == 1
    duplicates = [item for item in result.reasons if item.get("label") == "Same" and item.get("details") == "duplicate"]
    assert len(duplicates) == 1


def test_allow_helper_matches_verify_result():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(valid=True, allowed=True, verdict="allow"),
        rollout=_RolloutDecision(enabled=True, allowed=True, verdict="allow"),
        adapter_probe=_AdapterProbeResult(ok=True, installed=True, runtime="openclaw", adapter="openclaw"),
    )

    allowed = verifier.allow(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert allowed is True


def test_allow_helper_false_when_verification_fails():
    verifier, signing, release, registry = _build(
        verification=_VerificationResult(valid=False, allowed=False, verdict="block"),
    )

    allowed = verifier.allow(
        runtime="openclaw",
        bundle=_bundle(),
        signature="bad-signature",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="execute",
    )

    assert allowed is False
