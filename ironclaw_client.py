import os
from typing import Literal, TypedDict, List

import httpx


Verdict = Literal["allow", "warn", "quarantine", "block"]


class ScanResult(TypedDict):
    scan_id: str | None
    verdict: Verdict
    summary: str
    target_type: str
    target_value: str
    risk_score: int
    matched_patterns: List[str]
    risky_files: List[str]
    checks_loaded: List[str]
    failed_checks: List[str]
    quarantine_reason: str | None
    review_status: str | None
    untrusted: bool


class PromptBundleResult(TypedDict, total=False):
    user_prompt: dict
    retrieved_doc: dict
    tool_output: dict
    model_output: dict
    highest_verdict: Verdict
    should_halt: bool
    should_warn: bool


class IronclawClient:
    def __init__(self, base_url: str | None = None, timeout: float = 5.0):
        self.base_url = base_url or os.environ.get("IRONCLAW_BASE_URL", "http://localhost:8000")
        self.timeout = timeout

    def scan_text(self, text: str) -> ScanResult:
        url = f"{self.base_url}/scan/"
        payload = {"target_type": "text", "target_value": text}
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return {
            "scan_id": data.get("scan_id"),
            "verdict": data.get("verdict", "block"),
            "summary": data.get("summary", ""),
            "target_type": data.get("target_type", "text"),
            "target_value": data.get("target_value", text),
            "risk_score": data.get("risk_score", 0),
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
        url = f"{self.base_url}/policy/guard-bundle"
        payload = {
            "user_prompt": user_prompt,
            "retrieved_doc": retrieved_doc,
            "tool_output": tool_output,
            "model_output": model_output,
        }
        clean_payload = {k: v for k, v in payload.items() if v is not None}

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, json=clean_payload)
            resp.raise_for_status()
            data = resp.json()

        highest_verdict: Verdict = data.get("highest_verdict", "block")
        should_halt: bool = data.get("should_halt", True)

        if should_halt:
            # Prefer the user_prompt summary; fall back to model_output or generic
            user_ctx = data.get("user_prompt") or {}
            model_ctx = data.get("model_output") or {}
            summary = (
                user_ctx.get("summary")
                or model_ctx.get("summary")
                or "No summary provided."
            )
            raise RuntimeError(
                f"IronClaw policy halted bundle with verdict={highest_verdict!r}: {summary}"
            )

        return {
            "user_prompt": data.get("user_prompt", {}),
            "retrieved_doc": data.get("retrieved_doc", {}),
            "tool_output": data.get("tool_output", {}),
            "model_output": data.get("model_output", {}),
            "highest_verdict": highest_verdict,
            "should_halt": should_halt,
            "should_warn": data.get("should_warn", True),
        }