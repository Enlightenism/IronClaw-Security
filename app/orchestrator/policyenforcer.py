from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def _dedup_rules(rules: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _dedup_reasons(reasons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for r in reasons:
        key = (r.get("label"), r.get("details"), r.get("source"))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


@runtime_checkable
class PolicyBundleSigningServiceProto(Protocol):
    def verify_bundle(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class PolicyOverrideServiceProto(Protocol):
    def evaluate(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class ReleasePolicyServiceProto(Protocol):
    def evaluate(self, **kwargs: Any) -> Any: ...


@dataclass(slots=True)
class EnforcerDecision:
    allowed: bool
    verdict: str
    bundle_id: str
    version: str
    runtime: str
    override_active: bool
    rollout_enabled: bool
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[dict[str, Any]] = field(default_factory=list)
    bundle_verification: dict[str, Any] = field(default_factory=dict)
    override_evaluation: dict[str, Any] = field(default_factory=dict)
    rollout_evaluation: dict[str, Any] = field(default_factory=dict)
    evaluated_at: str = field(default_factory=_utcnow)

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
            "reasons": [dict(r) for r in self.reasons],
            "bundleverification": dict(self.bundle_verification),
            "overrideevaluation": dict(self.override_evaluation),
            "rolloutevaluation": dict(self.rollout_evaluation),
            "evaluatedat": self.evaluated_at,
        }


class PolicyEnforcer:
    def __init__(
        self,
        *,
        policy_bundle_signing_service: PolicyBundleSigningServiceProto,
        policy_override_service: PolicyOverrideServiceProto,
        release_policy_service: ReleasePolicyServiceProto,
    ) -> None:
        self._signing = policy_bundle_signing_service
        self._overrides = policy_override_service
        self._release = release_policy_service

    def evaluate(
        self,
        *,
        bundle: dict[str, Any] | None,
        signature: str,
        secret: str,
        manifest: dict[str, Any],
        runtime: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> EnforcerDecision:
        context = context or {}
        normalized_runtime = _normalize(runtime)

        if not bundle:
            return self._early_block(
                rule="missing_bundle",
                details="bundle is absent or None",
                runtime=normalized_runtime,
                bundle_id="",
                version="",
            )

        bundle_id: str = (bundle.get("bundle_id") or "").strip()
        version: str = (bundle.get("version") or "").strip()

        if not normalized_runtime:
            return self._early_block(
                rule="missing_runtime",
                details="runtime is absent or empty",
                runtime="",
                bundle_id=bundle_id,
                version=version,
            )

        verification = self._signing.verify_bundle(
            bundle=bundle,
            signature=signature,
            secret=secret,
            manifest=manifest,
            runtime=normalized_runtime,
            action=action,
            context=context,
        )

        bundle_verification_dict = (
            verification.as_dict()
            if hasattr(verification, "as_dict")
            else dict(verification) if isinstance(verification, dict)
            else {}
        )

        v_valid: bool = bool(getattr(verification, "valid", bundle_verification_dict.get("valid", False)))
        v_allowed: bool = bool(getattr(verification, "allowed", bundle_verification_dict.get("allowed", False)))
        v_verdict: str = str(getattr(verification, "verdict", bundle_verification_dict.get("verdict", "block")))
        v_rules: list[str] = list(getattr(verification, "matched_rules", bundle_verification_dict.get("matchedrules", [])))
        v_reasons: list[dict[str, Any]] = list(getattr(verification, "reasons", bundle_verification_dict.get("reasons", [])))

        if not v_valid:
            return EnforcerDecision(
                allowed=False,
                verdict=v_verdict if v_verdict in {"block", "reject"} else "block",
                bundle_id=bundle_id,
                version=version,
                runtime=normalized_runtime,
                override_active=False,
                rollout_enabled=False,
                matched_rules=_dedup_rules(v_rules),
                reasons=_dedup_reasons(v_reasons),
                bundle_verification=bundle_verification_dict,
                override_evaluation={},
                rollout_evaluation={},
            )

        override = self._overrides.evaluate(
            bundle=bundle,
            runtime=normalized_runtime,
            action=action,
            context=context,
        )

        override_dict = (
            override.as_dict()
            if hasattr(override, "as_dict")
            else dict(override) if isinstance(override, dict)
            else {}
        )

        o_active: bool = bool(getattr(override, "active", override_dict.get("active", False)))
        o_allowed: bool = bool(getattr(override, "allowed", override_dict.get("allowed", False)))
        o_rules: list[str] = list(getattr(override, "matched_rules", override_dict.get("matchedrules", [])))
        o_reasons: list[dict[str, Any]] = list(getattr(override, "reasons", override_dict.get("reasons", [])))

        if o_active and not o_allowed:
            combined_rules = _dedup_rules(v_rules + o_rules)
            combined_reasons = _dedup_reasons(v_reasons + o_reasons)
            return EnforcerDecision(
                allowed=False,
                verdict="block",
                bundle_id=bundle_id,
                version=version,
                runtime=normalized_runtime,
                override_active=True,
                rollout_enabled=False,
                matched_rules=combined_rules,
                reasons=combined_reasons,
                bundle_verification=bundle_verification_dict,
                override_evaluation=override_dict,
                rollout_evaluation={},
            )

        override_lifts: bool = o_active and o_allowed and not v_allowed

        rollout = self._release.evaluate(
            bundle=bundle,
            runtime=normalized_runtime,
            action=action,
            context=context,
        )

        rollout_dict = (
            rollout.as_dict()
            if hasattr(rollout, "as_dict")
            else dict(rollout) if isinstance(rollout, dict)
            else {}
        )

        r_enabled: bool = bool(getattr(rollout, "enabled", rollout_dict.get("enabled", False)))
        r_allowed: bool = bool(getattr(rollout, "allowed", rollout_dict.get("allowed", False)))
        r_rules: list[str] = list(getattr(rollout, "matched_rules", rollout_dict.get("matchedrules", [])))
        r_reasons: list[dict[str, Any]] = list(getattr(rollout, "reasons", rollout_dict.get("reasons", [])))

        combined_rules = _dedup_rules(v_rules + o_rules + r_rules)
        combined_reasons = _dedup_reasons(v_reasons + o_reasons + r_reasons)

        if not r_enabled or not r_allowed:
            return EnforcerDecision(
                allowed=False,
                verdict="block",
                bundle_id=bundle_id,
                version=version,
                runtime=normalized_runtime,
                override_active=o_active,
                rollout_enabled=False,
                matched_rules=combined_rules,
                reasons=combined_reasons,
                bundle_verification=bundle_verification_dict,
                override_evaluation=override_dict,
                rollout_evaluation=rollout_dict,
            )

        if override_lifts or (o_active and o_allowed):
            final_verdict = "allow"
            final_allowed = True
        elif not v_allowed:
            final_verdict = v_verdict
            final_allowed = False
        else:
            final_verdict = v_verdict
            final_allowed = final_verdict == "allow"

        return EnforcerDecision(
            allowed=final_allowed,
            verdict=final_verdict,
            bundle_id=bundle_id,
            version=version,
            runtime=normalized_runtime,
            override_active=o_active,
            rollout_enabled=r_enabled,
            matched_rules=combined_rules,
            reasons=combined_reasons,
            bundle_verification=bundle_verification_dict,
            override_evaluation=override_dict,
            rollout_evaluation=rollout_dict,
        )

    def allow(
        self,
        *,
        bundle: dict[str, Any] | None,
        signature: str,
        secret: str,
        manifest: dict[str, Any],
        runtime: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        return self.evaluate(
            bundle=bundle,
            signature=signature,
            secret=secret,
            manifest=manifest,
            runtime=runtime,
            action=action,
            context=context,
        ).allowed

    @staticmethod
    def _early_block(
        *,
        rule: str,
        details: str,
        runtime: str,
        bundle_id: str,
        version: str,
    ) -> EnforcerDecision:
        return EnforcerDecision(
            allowed=False,
            verdict="block",
            bundle_id=bundle_id,
            version=version,
            runtime=runtime,
            override_active=False,
            rollout_enabled=False,
            matched_rules=[rule],
            reasons=[{"source": "enforcer", "label": rule, "details": details, "score": 100}],
            bundle_verification={},
            override_evaluation={},
            rollout_evaluation={},
        )


def build_policy_enforcer(
    *,
    policy_bundle_signing_service: PolicyBundleSigningServiceProto,
    policy_override_service: PolicyOverrideServiceProto,
    release_policy_service: ReleasePolicyServiceProto,
) -> PolicyEnforcer:
    return PolicyEnforcer(
        policy_bundle_signing_service=policy_bundle_signing_service,
        policy_override_service=policy_override_service,
        release_policy_service=release_policy_service,
    )