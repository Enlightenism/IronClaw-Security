from __future__ import annotations

from typing import Any


def _dedup_list(items: list[Any]) -> list[Any]:
    seen: list[Any] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _block_response(
    *,
    matched_rules: list[str],
    reasons: list[dict[str, Any]] | None = None,
    verdict: str = "block",
) -> dict[str, Any]:
    return {
        "allowed": False,
        "verdict": verdict,
        "runtime": "groq",
        "policy": {
            "bundleid": "",
            "version": "",
            "matchedrules": matched_rules,
            "reasons": reasons or [],
            "overrideactive": False,
            "rolloutenabled": True,
        },
        "result": None,
    }


class _GroqSecurityBrain:
    def __init__(self, policy_enforcer: Any, groq_client: Any) -> None:
        self._enforcer = policy_enforcer
        self._client = groq_client

    def evaluate_request(self, **kwargs: Any) -> dict[str, Any]:
        bundle = kwargs.get("bundle")
        signature = kwargs.get("signature", "")
        secret = kwargs.get("secret", "")
        manifest = kwargs.get("manifest") or {}
        action = kwargs.get("action", "")
        prompt = kwargs.get("prompt", "")
        context = kwargs.get("context") or {}

        # --- Pre-policy guard checks ---
        if not bundle:
            return _block_response(matched_rules=["missing_bundle"])
        if not signature:
            return _block_response(matched_rules=["missing_signature"])

        # --- Policy evaluation ---
        decision = self._enforcer.evaluate(
            bundle=bundle,
            signature=signature,
            secret=secret,
            manifest=manifest,
            runtime="groq",
            action=action,
            prompt=prompt,
            context=context,
        )

        allowed: bool = decision.allowed
        verdict: str = decision.verdict
        policy_dict = decision.as_dict()

        policy_dict["matchedrules"] = _dedup_list(policy_dict.get("matchedrules", []))
        policy_dict["reasons"] = _dedup_list(policy_dict.get("reasons", []))

        if not allowed:
            return {
                "allowed": False,
                "verdict": verdict,
                "runtime": "groq",
                "policy": policy_dict,
                "result": None,
            }

        # --- Groq client call ---
        try:
            groq_result = self._client.generate(
                prompt=prompt,
                context=context,
                action=action,
            )
        except Exception as exc:
            policy_dict["matchedrules"] = _dedup_list(
                policy_dict["matchedrules"] + ["runtime_execution_error"],
            )
            return {
                "allowed": False,
                "verdict": "error",
                "runtime": "groq",
                "policy": policy_dict,
                "result": {"error": str(exc)},
            }

        return {
            "allowed": True,
            "verdict": verdict,
            "runtime": "groq",
            "policy": policy_dict,
            "result": groq_result,
        }

    def allow_request(self, **kwargs: Any) -> bool:
        bundle = kwargs.get("bundle")
        signature = kwargs.get("signature", "")
        if not bundle or not signature:
            return False
        decision = self._enforcer.allow(
            bundle=bundle,
            signature=signature,
            secret=kwargs.get("secret", ""),
            manifest=kwargs.get("manifest") or {},
            runtime="groq",
            action=kwargs.get("action", ""),
            prompt=kwargs.get("prompt", ""),
            context=kwargs.get("context") or {},
        )
        return bool(decision)


def build_groq_security_brain(
    *,
    policy_enforcer: Any,
    groq_client: Any,
) -> _GroqSecurityBrain:
    return _GroqSecurityBrain(
        policy_enforcer=policy_enforcer,
        groq_client=groq_client,
    )