"""API-side client for the host sandbox broker. Fail closed: any error is a block verdict."""

from __future__ import annotations

import os
from typing import Any

import httpx

SANDBOX_BROKER_URL_ENV = "SANDBOX_BROKER_URL"
SANDBOX_BROKER_TOKEN_ENV = "SANDBOX_BROKER_TOKEN"
DEFAULT_SANDBOX_BROKER_URL = "http://host.docker.internal:8088"
BROKER_TIMEOUT_MARGIN_SECONDS = 5.0
BROKER_CONNECT_TIMEOUT_SECONDS = 2.0
BROKER_HEALTH_TIMEOUT_SECONDS = 2.0
BROKER_TOKEN_HEADER = "X-Broker-Token"


def broker_block(reason: str) -> dict[str, Any]:
    return {"verdict": "block", "status": "unavailable", "executor": "docker", "reason": reason, "untrusted": True}


class SandboxBrokerClient:
    def __init__(self, broker_url: str | None = None, broker_token: str | None = None) -> None:
        url = broker_url or os.environ.get(SANDBOX_BROKER_URL_ENV) or DEFAULT_SANDBOX_BROKER_URL
        self._broker_url = url.rstrip("/")
        self._broker_token = broker_token if broker_token is not None else os.environ.get(SANDBOX_BROKER_TOKEN_ENV, "").strip()

    def run(
        self,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
        read_only_fs: bool = True,
        network_enabled: bool = False,
    ) -> dict[str, Any]:
        if not self._broker_token:
            return broker_block("broker_unconfigured")

        body = {
            "action_type": action_type,
            "target": target,
            "payload": payload,
            "timeout_seconds": timeout_seconds,
            "read_only_fs": read_only_fs,
            "network_enabled": network_enabled,
        }
        timeout = httpx.Timeout(timeout_seconds + BROKER_TIMEOUT_MARGIN_SECONDS, connect=BROKER_CONNECT_TIMEOUT_SECONDS)
        try:
            response = httpx.post(
                f"{self._broker_url}/run",
                json=body,
                headers={BROKER_TOKEN_HEADER: self._broker_token},
                timeout=timeout,
            )
        except (httpx.HTTPError, TypeError, ValueError):
            return broker_block("broker_unreachable")

        if not response.is_success:
            return broker_block("broker_error")

        try:
            data = response.json()
        except ValueError:
            return broker_block("invalid_response")

        if not isinstance(data, dict) or data.get("verdict") not in {"allow", "block"}:
            return broker_block("invalid_response")
        return data

    def health(self) -> dict[str, Any]:
        if not self._broker_token:
            return {"reachable": False, "reason": "broker_unconfigured"}
        timeout = httpx.Timeout(BROKER_HEALTH_TIMEOUT_SECONDS, connect=BROKER_CONNECT_TIMEOUT_SECONDS)
        try:
            response = httpx.get(f"{self._broker_url}/health", timeout=timeout)
        except (httpx.HTTPError, TypeError, ValueError):
            return {"reachable": False, "reason": "broker_unreachable"}
        if not response.is_success:
            return {"reachable": False, "reason": "broker_error"}
        try:
            data = response.json()
        except ValueError:
            data = {}
        if isinstance(data, dict) and isinstance(data.get("scanner_image"), str):
            return {"reachable": True, "reason": None, "scanner_image": data["scanner_image"]}
        return {"reachable": True, "reason": None}
