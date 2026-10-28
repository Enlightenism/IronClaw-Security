from __future__ import annotations

from typing import Any, Literal

from app.services.prompt_guard_client import PromptGuardClient

GuardSecurityVerdict = Literal["allow", "block"]


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
    verdict: Literal["block"] = "block",
) -> dict[str, Any]:
    return {
        "allowed": False,
        "verdict": verdict,
        "runtime": "guard",
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


class _GuardSecurityBrain:
    def __init__(self, policy_enforcer: Any, prompt_guard_client: PromptGuardClient) -> None:
        self._enforcer = policy_enforcer
        self._prompt_guard = prompt_guard_client

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
            runtime="guard",
            action=action,
            prompt=prompt,
            context=context,
        )

        allowed = bool(decision.allowed) and decision.verdict == "allow"
        verdict: GuardSecurityVerdict = "allow" if allowed else "block"
        policy_dict = decision.as_dict()
        policy_dict["verdict"] = verdict
        if "allowed" in policy_dict:
            policy_dict["allowed"] = allowed

        policy_dict["matchedrules"] = _dedup_list(policy_dict.get("matchedrules", []))
        policy_dict["reasons"] = _dedup_list(policy_dict.get("reasons", []))

        if not allowed:
            return {
                "allowed": False,
                "verdict": verdict,
                "runtime": "guard",
                "policy": policy_dict,
                "result": None,
            }

        classification = self._prompt_guard.classify(prompt) if prompt.strip() else None
        if classification is None:
            reason = "guard_disabled" if not self._prompt_guard.enabled else "empty_prompt"
            return {
                "allowed": True,
                "verdict": verdict,
                "runtime": "guard",
                "policy": policy_dict,
                "result": {
                    "status": "not_classified",
                    "reason": reason,
                    "model_name": self._prompt_guard.model_path,
                },
            }

        classification_result = classification.to_dict()
        if classification.is_malicious:
            allowed = False
            verdict = "block"
            policy_dict["verdict"] = verdict
            if "allowed" in policy_dict:
                policy_dict["allowed"] = allowed
            policy_dict["matchedrules"] = _dedup_list(
                policy_dict["matchedrules"] + ["prompt_guard:malicious"],
            )
            policy_dict["reasons"] = _dedup_list(
                policy_dict["reasons"]
                + [
                    {
                        "label": "Prompt Guard classified the prompt as malicious",
                        "details": f"Malicious score: {classification.malicious_score:.3f}",
                    },
                ],
            )

        return {
            "allowed": allowed,
            "verdict": verdict,
            "runtime": "guard",
            "policy": policy_dict,
            "result": classification_result,
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
            runtime="guard",
            action=kwargs.get("action", ""),
            prompt=kwargs.get("prompt", ""),
            context=kwargs.get("context") or {},
        )
        return bool(decision)


def build_guard_security_brain(
    *,
    policy_enforcer: Any,
    prompt_guard_client: PromptGuardClient,
) -> _GuardSecurityBrain:
    return _GuardSecurityBrain(
        policy_enforcer=policy_enforcer,
        prompt_guard_client=prompt_guard_client,
    )
