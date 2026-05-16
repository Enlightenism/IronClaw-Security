from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal

import httpx

LlamaFirewallScanMode = Literal["enforce", "monitor", "dryrun"]
LlamaFirewallScanner = Literal["prompt_guard", "agent_alignment", "code_shield"]

_VALID_SCAN_MODES = {"enforce", "monitor", "dryrun"}
_VALID_SCANNERS: set[str] = {"prompt_guard", "agent_alignment", "code_shield"}

_ENDPOINT_MAP: dict[LlamaFirewallScanner, str] = {
    "prompt_guard": "scan/prompt",
    "agent_alignment": "scan/agent",
    "code_shield": "scan/code",
}


@dataclass
class LlamaFirewallClientConfig:
    """Configuration for the LlamaFirewall HTTP client.

    Environment variables (all prefixed IRONCLAW_LLAMAFIREWALL_):
      BASE_URL     — base URL of the LlamaFirewall scanning service
      API_KEY      — bearer token for the scanning API
      SCAN_MODE    — enforce | monitor | dryrun  (default: enforce)
      TIMEOUT_MS   — per-request timeout in ms   (default: 10000, range 1000-60000)
      MAX_KB       — max payload size in KB       (default: 512, range 16-4096)
    """

    base_url: str
    api_key: str
    scan_mode: LlamaFirewallScanMode = "enforce"
    default_timeout_ms: int = 10000
    max_payload_kb: int = 512
    enable_prompt_guard: bool = True
    enable_agent_alignment: bool = True
    enable_code_shield: bool = True

    @classmethod
    def from_env(cls) -> LlamaFirewallClientConfig:
        import os

        base_url = os.environ.get("IRONCLAW_LLAMAFIREWALL_BASE_URL", "").rstrip("/")
        api_key = os.environ.get("IRONCLAW_LLAMAFIREWALL_API_KEY", "")

        if not base_url or not api_key:
            raise RuntimeError(
                "IRONCLAW_LLAMAFIREWALL_BASE_URL and IRONCLAW_LLAMAFIREWALL_API_KEY must be set.",
            )

        mode = os.environ.get("IRONCLAW_LLAMAFIREWALL_SCAN_MODE", "enforce").lower()
        if mode not in _VALID_SCAN_MODES:
            mode = "enforce"

        def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(os.environ.get(name, str(default)))
            except ValueError:
                return default
            return max(minimum, min(maximum, value))

        timeout_ms = _int_env("IRONCLAW_LLAMAFIREWALL_TIMEOUT_MS", 10000, 1000, 60000)
        max_kb = _int_env("IRONCLAW_LLAMAFIREWALL_MAX_KB", 512, 16, 4096)

        return cls(
            base_url=base_url,
            api_key=api_key,
            scan_mode=mode,  # type: ignore[arg-type]
            default_timeout_ms=timeout_ms,
            max_payload_kb=max_kb,
            enable_prompt_guard=True,
            enable_agent_alignment=True,
            enable_code_shield=True,
        )


class LlamaFirewallClient:
    """Thin synchronous HTTP client for the LlamaFirewall scanning API.

    Provides three scanning surfaces:
      - scan_prompt        → PromptGuard 2   (/scan/prompt)
      - scan_agent_action  → AgentAlignment  (/scan/agent)
      - scan_code          → CodeShield      (/scan/code)

    All methods return a normalized dict with at minimum:
      {
        "scanner":  str,
        "verdict":  "safe" | "unsafe" | "unknown",
        "risk_score": int,
        "categories": list[str],
        "details": dict,
        "raw": dict,
      }

    When scan_mode is "dryrun" all methods return a bypassed response without
    making any network calls.  When a scanner is disabled in config the method
    returns a bypassed response immediately.
    """

    def __init__(
        self,
        config: LlamaFirewallClientConfig,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._config = config
        timeout_seconds = config.default_timeout_ms / 1000.0
        self._client = client or httpx.Client(timeout=timeout_seconds)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._config.api_key}",
            "Content-Type": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self._config.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _bypassed(self, scanner: str, reason: str) -> dict[str, Any]:
        return {
            "scanner": scanner,
            "verdict": "unknown",
            "risk_score": 0,
            "categories": [],
            "details": {},
            "bypassed": True,
            "bypass_reason": reason,
            "raw": {},
        }

    def _size_exceeded(self, scanner: str, size_kb: float) -> dict[str, Any]:
        return {
            "scanner": scanner,
            "verdict": "unsafe",
            "risk_score": 100,
            "categories": ["payload_too_large"],
            "details": {"size_kb": size_kb, "max_kb": self._config.max_payload_kb},
            "bypassed": False,
            "bypass_reason": None,
            "raw": {},
        }

    def _normalize_response(
        self,
        scanner: str,
        raw: dict[str, Any],
    ) -> dict[str, Any]:
        """Normalize a raw LlamaFirewall API response to the IronClaw shape."""
        verdict = str(raw.get("verdict", raw.get("result", "unknown"))).lower()
        if verdict not in {"safe", "unsafe", "unknown"}:
            verdict = "unknown"

        risk_score = int(raw.get("risk_score", raw.get("score", 0)))
        risk_score = max(0, min(100, risk_score))

        raw_cats = raw.get("categories", raw.get("labels", []))
        categories: list[str] = [str(c) for c in raw_cats] if isinstance(raw_cats, list) else []

        details: dict[str, Any] = {}
        for key in ("message", "reason", "explanation", "details", "metadata"):
            if key in raw:
                details[key] = raw[key]

        return {
            "scanner": scanner,
            "verdict": verdict,
            "risk_score": risk_score,
            "categories": categories,
            "details": details,
            "bypassed": False,
            "bypass_reason": None,
            "raw": raw,
        }

    def _check_payload_size(self, payload: dict[str, Any]) -> float:
        """Return payload size in KB."""
        encoded = json.dumps(payload, ensure_ascii=False)
        return len(encoded.encode("utf-8")) / 1024.0

    def _post(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = self._url(endpoint)
        resp = self._client.post(url, headers=self._headers(), json=payload)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    # ------------------------------------------------------------------
    # Public scanning methods
    # ------------------------------------------------------------------

    def scan_prompt(
        self,
        *,
        prompt: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit a prompt to PromptGuard 2 for jailbreak / injection scanning.

        Returns a normalized scan result dict.
        """
        scanner: LlamaFirewallScanner = "prompt_guard"

        if not self._config.enable_prompt_guard:
            return self._bypassed(scanner, "prompt_guard disabled in config")

        if self._config.scan_mode == "dryrun":
            return self._bypassed(scanner, "dryrun mode — no network call made")

        payload: dict[str, Any] = {"prompt": prompt}
        if agent_id:
            payload["agent_id"] = agent_id
        if session_id:
            payload["session_id"] = session_id
        if metadata:
            payload["metadata"] = metadata

        size_kb = self._check_payload_size(payload)
        if size_kb > self._config.max_payload_kb:
            return self._size_exceeded(scanner, size_kb)

        raw = self._post(_ENDPOINT_MAP[scanner], payload)
        return self._normalize_response(scanner, raw)

    def scan_agent_action(
        self,
        *,
        action_type: str,
        target: str,
        content: str = "",
        agent_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit an agent action to AgentAlignmentCheck for goal-hijacking / unsafe
        chain-of-thought detection.

        Returns a normalized scan result dict.
        """
        scanner: LlamaFirewallScanner = "agent_alignment"

        if not self._config.enable_agent_alignment:
            return self._bypassed(scanner, "agent_alignment disabled in config")

        if self._config.scan_mode == "dryrun":
            return self._bypassed(scanner, "dryrun mode — no network call made")

        payload: dict[str, Any] = {
            "action_type": action_type,
            "target": target,
            "content": content,
        }
        if agent_id:
            payload["agent_id"] = agent_id
        if session_id:
            payload["session_id"] = session_id
        if metadata:
            payload["metadata"] = metadata

        size_kb = self._check_payload_size(payload)
        if size_kb > self._config.max_payload_kb:
            return self._size_exceeded(scanner, size_kb)

        raw = self._post(_ENDPOINT_MAP[scanner], payload)
        return self._normalize_response(scanner, raw)

    def scan_code(
        self,
        *,
        code: str,
        language: str = "unknown",
        agent_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit code to CodeShield for insecure / malicious code detection.

        Returns a normalized scan result dict.
        """
        scanner: LlamaFirewallScanner = "code_shield"

        if not self._config.enable_code_shield:
            return self._bypassed(scanner, "code_shield disabled in config")

        if self._config.scan_mode == "dryrun":
            return self._bypassed(scanner, "dryrun mode — no network call made")

        payload: dict[str, Any] = {"code": code, "language": language}
        if agent_id:
            payload["agent_id"] = agent_id
        if session_id:
            payload["session_id"] = session_id
        if metadata:
            payload["metadata"] = metadata

        size_kb = self._check_payload_size(payload)
        if size_kb > self._config.max_payload_kb:
            return self._size_exceeded(scanner, size_kb)

        raw = self._post(_ENDPOINT_MAP[scanner], payload)
        return self._normalize_response(scanner, raw)

    def scan_all(
        self,
        *,
        prompt: str | None = None,
        action_type: str | None = None,
        target: str | None = None,
        content: str = "",
        code: str | None = None,
        language: str = "unknown",
        agent_id: str | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run all applicable scanners and return a combined result.

        Returns:
          {
            "overall_verdict": "safe" | "unsafe" | "unknown",
            "overall_risk_score": int,
            "scanners_run": list[str],
            "results": dict[scanner_name, normalized_result],
          }
        """
        results: dict[str, dict[str, Any]] = {}

        if prompt is not None:
            results["prompt_guard"] = self.scan_prompt(
                prompt=prompt,
                agent_id=agent_id,
                session_id=session_id,
                metadata=metadata,
            )

        if action_type is not None and target is not None:
            results["agent_alignment"] = self.scan_agent_action(
                action_type=action_type,
                target=target,
                content=content,
                agent_id=agent_id,
                session_id=session_id,
                metadata=metadata,
            )

        if code is not None:
            results["code_shield"] = self.scan_code(
                code=code,
                language=language,
                agent_id=agent_id,
                session_id=session_id,
                metadata=metadata,
            )

        active = [r for r in results.values() if not r.get("bypassed", False)]

        if not active:
            overall_verdict = "unknown"
            overall_risk = 0
        elif any(r["verdict"] == "unsafe" for r in active):
            overall_verdict = "unsafe"
            overall_risk = max(r["risk_score"] for r in active)
        elif all(r["verdict"] == "safe" for r in active):
            overall_verdict = "safe"
            overall_risk = max(r["risk_score"] for r in active)
        else:
            overall_verdict = "unknown"
            overall_risk = max(r["risk_score"] for r in active)

        return {
            "overall_verdict": overall_verdict,
            "overall_risk_score": overall_risk,
            "scanners_run": list(results.keys()),
            "results": results,
        }

    def close(self) -> None:
        self._client.close()
