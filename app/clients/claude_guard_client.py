from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx

GuardMode = Literal["enforce", "assist", "dryrun"]


@dataclass
class ClaudeGuardClientConfig:
    guard_base_url: str
    api_key: str
    guard_mode: GuardMode = "enforce"
    default_timeout_ms: int = 8000
    max_payload_kb: int = 256
    use_bundle_guard: bool = True
    use_guard_execute: bool = True

    @classmethod
    def from_env(cls) -> ClaudeGuardClientConfig:
        import os

        base_url = os.environ.get("IRONCLAW_GUARD_BASE_URL", "").rstrip("/")
        api_key = os.environ.get("IRONCLAW_GUARD_API_KEY", "")

        if not base_url or not api_key:
            raise RuntimeError(
                "IRONCLAW_GUARD_BASE_URL and IRONCLAW_GUARD_API_KEY must be set."
            )

        mode = os.environ.get("IRONCLAW_GUARD_MODE", "enforce").lower()
        if mode not in {"enforce", "assist", "dryrun"}:
            mode = "enforce"

        def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(os.environ.get(name, str(default)))
            except ValueError:
                return default
            return max(minimum, min(maximum, value))

        timeout_ms = _int_env("IRONCLAW_GUARD_TIMEOUT_MS", 8000, 1000, 30000)
        max_kb = _int_env("IRONCLAW_GUARD_MAX_PAYLOAD_KB", 256, 16, 2048)

        return cls(
            guard_base_url=base_url,
            api_key=api_key,
            guard_mode=mode,  # type: ignore[arg-type]
            default_timeout_ms=timeout_ms,
            max_payload_kb=max_kb,
            use_bundle_guard=True,
            use_guard_execute=True,
        )


class ClaudeGuardClient:
    """
    Thin client for Claude Code proxy/tooling to talk to IronClaw.

    This client is intentionally minimal and synchronous so it can be
    dropped into existing proxy code paths without refactors.
    """

    def __init__(
        self,
        config: ClaudeGuardClientConfig,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._config = config
        timeout_seconds = config.default_timeout_ms / 1000.0
        self._client = client or httpx.Client(timeout=timeout_seconds)

    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self._config.api_key,
            "Content-Type": "application/json",
        }

    def _guard_url(self, path: str) -> str:
        return f"{self._config.guard_base_url.rstrip('/')}/{path.lstrip('/')}"

    def guard_execute(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Send an ExecuteRequest-style payload to /guard/execute.

        Expected response (high level):
          - status / verdict fields indicating allow/review/block
          - optional reason / messages for UI display
        """
        if not self._config.use_guard_execute:
            return {"status": "bypassed", "reason": "guard_execute disabled in config"}

        url = self._guard_url("guard/execute")
        resp = self._client.post(url, headers=self._headers(), json=payload)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def guard_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        """
        Send a prompt/output bundle to /policy/guard-bundle.

        Typical bundle keys:
          - userprompt
          - retrieveddoc
          - tooloutput
          - modeloutput
        """
        if not self._config.use_bundle_guard:
            return {"status": "bypassed", "reason": "guard_bundle disabled in config"}

        # Soft size guard; Claude Code proxy should already keep bundles small.
        import json

        encoded = json.dumps(bundle, ensure_ascii=False)
        size_kb = len(encoded.encode("utf-8")) / 1024.0
        if size_kb > self._config.max_payload_kb:
            return {
                "status": "blocked",
                "reason": "Bundle too large for guard_policy; reduce payload or increase IRONCLAW_GUARD_MAX_PAYLOAD_KB.",
                "size_kb": size_kb,
            }

        url = self._guard_url("policy/guard-bundle")
        resp = self._client.post(url, headers=self._headers(), json=bundle)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]

    def close(self) -> None:
        self._client.close()