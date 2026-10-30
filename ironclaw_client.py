from __future__ import annotations

import os
from typing import Any, Final, Literal, TypedDict

import httpx

from app.config import RISK_THRESHOLD_BLOCK_MIN
from ironclaw_sdk.models import GuardBundleRequest, GuardBundleResponse

Verdict = Literal["allow", "block"]

_DEFAULT_BASE_URL: Final[str] = "http://localhost:8000"


def _normalize_verdict(value: Any) -> Verdict:
    return "allow" if value == "allow" else "block"


def _normalize_risk_score(value: Any, verdict: Verdict) -> int:
    score = int(value or 0)
    return max(score, RISK_THRESHOLD_BLOCK_MIN) if verdict == "block" else score


class ScanResult(TypedDict):
    scan_id: str | None
    verdict: Verdict
    summary: str
    target_type: str
    target_value: str
    risk_score: int
    matched_patterns: list[str]
    risky_files: list[str]
    checks_loaded: list[str]
    failed_checks: list[str]
    quarantine_reason: str | None
    review_status: str | None
    untrusted: bool


class PromptBundleResult(TypedDict, total=False):
    """Return shape for guard_prompt_bundle.

    Mirrors GuardBundleResponse from ironclaw_sdk.models — kept as a
    TypedDict for backward compatibility with callers that do dict-style
    access. The canonical Pydantic model is GuardBundleResponse; do not
    diverge this shape from it.

    ``should_halt`` is always present (total=False does not make it
    absent — callers must check it before proceeding).
    """

    user_prompt: dict[str, Any]
    retrieved_doc: dict[str, Any]
    tool_output: dict[str, Any]
    model_output: dict[str, Any]
    highest_verdict: Verdict
    should_halt: bool
    should_warn: Literal[False]


class IronClawScanClient:
    """Thin HTTP client for IronClaw scan and guard-bundle endpoints.

    Renamed from IronclawClient to IronClawScanClient to prevent import
    collision with IronclawClient in ironclaw_sdk/client.py.

    guard_prompt_bundle does NOT raise on a halt verdict — callers must
    inspect ``result["should_halt"]`` and decide how to proceed. This
    preserves caller agency and matches the SDK contract in
    ironclaw_sdk.client.IronclawClient.guard_bundle.
    """

    def __init__(self, base_url: str | None = None, timeout: float = 5.0) -> None:
        self.base_url = (base_url or os.environ.get("IRONCLAW_BASE_URL", _DEFAULT_BASE_URL)).rstrip("/")
        self.timeout = timeout

    def scan_text(self, text: str) -> ScanResult:
        url = f"{self.base_url}/scan/"
        payload = {"target_type": "text", "target_value": text}
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        verdict = _normalize_verdict(data.get("verdict"))
        return {
            "scan_id": data.get("scan_id"),
            "verdict": verdict,
            "summary": data.get("summary", ""),
            "target_type": data.get("target_type", "text"),
            "target_value": data.get("target_value", text),
            "risk_score": _normalize_risk_score(data.get("risk_score"), verdict),
            "matched_patterns": data.get("matched_patterns", []),
            "risky_files": data.get("risky_files", []),
            "checks_loaded": data.get("checks_loaded", []),
            "failed_checks": data.get("failed_checks", []),
            "quarantine_reason": data.get("quarantine_reason"),
            "review_status": data.get("review_status", "none"),
            "untrusted": data.get("untrusted", False),
        }

    def guard_prompt_bundle(
        self,
        user_prompt: str | None = None,
        retrieved_doc: str | None = None,
        tool_output: str | None = None,
        model_output: str | None = None,
    ) -> PromptBundleResult:
        """Submit a multi-slot prompt bundle for policy evaluation.

        Returns a PromptBundleResult dict that always includes
        ``should_halt``. Callers are responsible for acting on that flag —
        this method never raises on a block verdict.

        Uses GuardBundleRequest from ironclaw_sdk.models to serialise the
        request so the wire format stays in sync with the SDK contract.
        """
        url = f"{self.base_url}/policy/guard-bundle"

        request = GuardBundleRequest(
            user_prompt=user_prompt,
            retrieved_doc=retrieved_doc,
            tool_output=tool_output,
            model_output=model_output,
        )

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, content=request.model_dump_json(exclude_none=True))
            resp.raise_for_status()
            data = resp.json()

        # Validate through the canonical SDK response model so shape drift
        # is caught at parse time rather than silently at the call site.
        bundle = GuardBundleResponse.model_validate(data)

        def _slot(val: Any) -> dict[str, Any]:
            if val is None:
                return {}
            if isinstance(val, dict):
                return val
            # GuardBundleSlotResult or similar Pydantic model
            return val.model_dump()

        return {
            "user_prompt": _slot(bundle.user_prompt),
            "retrieved_doc": _slot(bundle.retrieved_doc),
            "tool_output": _slot(bundle.tool_output),
            "model_output": _slot(bundle.model_output),
            "highest_verdict": bundle.highest_verdict,  # type: ignore[typeddict-item]
            "should_halt": bundle.should_halt,
            "should_warn": False,
        }


# Backward-compat alias — preserves any existing imports of the old name.
IronclawClient = IronClawScanClient


__all__ = [
    "IronClawScanClient",
    "IronclawClient",
    "GuardBundleRequest",
    "GuardBundleResponse",
    "PromptBundleResult",
    "ScanResult",
    "Verdict",
]
