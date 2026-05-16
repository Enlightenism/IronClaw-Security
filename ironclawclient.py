from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import json
import os
from typing import Any, Final

import httpx

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0


class IronClawClientError(RuntimeError):
    """Base client error for IronClaw API interactions."""


class IronClawRequestError(IronClawClientError):
    """Raised when the request could not be completed."""


class IronClawHTTPStatusError(IronClawClientError):
    """Raised when the API responds with a non-2xx status code."""

    def __init__(self, message: str, *, status_code: int, detail: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class IronClawResponse:
    method: str
    path: str
    status_code: int
    payload: Any
    headers: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _env_base_url() -> str:
    value = os.environ.get("IRONCLAW_BASE_URL")
    return value.rstrip("/") if value else DEFAULT_BASE_URL


def _env_timeout() -> float:
    value = os.environ.get("IRONCLAW_CLIENT_TIMEOUT_SECONDS")
    if not value:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(value.strip())
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    return timeout if timeout > 0 else DEFAULT_TIMEOUT_SECONDS


class IronClawInfraClient:
    """Synchronous API client for IronClaw infrastructure endpoints.

    Renamed from IronClawClient to IronClawInfraClient to prevent import
    collision with IronClawScanClient in ironclaw_client.py.

    Covers health checks, UI runtime inspection, backup control,
    and restore control.
    """

    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout: float | None = None,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> None:
        resolved_headers = {"Accept": "application/json"}
        if headers:
            resolved_headers.update(dict(headers))

        self._client = httpx.Client(
            base_url=(base_url or _env_base_url()).rstrip("/"),
            timeout=httpx.Timeout(timeout if timeout is not None else _env_timeout()),
            headers=resolved_headers,
            follow_redirects=follow_redirects,
        )

    @property
    def base_url(self) -> str:
        return str(self._client.base_url).rstrip("/")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> IronClawInfraClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
    ) -> IronClawResponse:
        try:
            response = self._client.request(method=method, url=path, params=params, json=json_body)
        except httpx.RequestError as exc:
            raise IronClawRequestError(f"{method.upper()} {path} failed: {exc}") from exc

        payload = self._decode_payload(response)

        if not (200 <= response.status_code < 300):
            detail = payload.get("detail") if isinstance(payload, dict) else payload
            raise IronClawHTTPStatusError(
                f"{method.upper()} {path} returned {response.status_code}",
                status_code=response.status_code,
                detail=detail,
            )

        return IronClawResponse(
            method=method.upper(),
            path=path,
            status_code=response.status_code,
            payload=payload,
            headers=dict(response.headers),
        )

    def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> IronClawResponse:
        return self.request("GET", path, params=params)

    def post(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Any = None,
    ) -> IronClawResponse:
        return self.request("POST", path, params=params, json_body=json_body)

    def health(self) -> dict[str, Any]:
        return self.get("/api/health").payload

    def health_liveness(self) -> dict[str, Any]:
        return self.get("/api/health/liveness").payload

    def health_readiness(self) -> dict[str, Any]:
        return self.get("/api/health/readiness").payload

    def system_status(self) -> dict[str, Any]:
        return self.get("/api/system/status").payload

    def ui_manifest(self) -> dict[str, Any]:
        return self.get("/api/ui/manifest").payload

    def ui_status(self) -> dict[str, Any]:
        return self.get("/api/ui/status/runtime").payload

    def ui_runtime_status(self) -> dict[str, Any]:
        return self.get("/api/ui/runtime/status").payload

    def backup_status(self) -> dict[str, Any]:
        return self.get("/api/backup").payload

    def backup_targets(self) -> list[dict[str, Any]]:
        payload = self.get("/api/backup/targets").payload
        return payload if isinstance(payload, list) else [payload]

    def backup_snapshot(self, target_name: str) -> dict[str, Any]:
        return self.post("/api/backup/snapshot", params={"target_name": target_name}).payload

    def backup_export(self, target_name: str) -> dict[str, Any]:
        return self.post("/api/backup/export", params={"target_name": target_name}).payload

    def backup_rotate(self, target_name: str) -> dict[str, Any]:
        return self.post("/api/backup/rotate", params={"target_name": target_name}).payload

    def backup_action(self, target_name: str, action: str) -> dict[str, Any]:
        return self.post(
            "/api/backup/action",
            json_body={"target_name": target_name, "action": action},
        ).payload

    def restore_status(self) -> dict[str, Any]:
        return self.get("/api/restore").payload

    def restore_targets(self) -> list[dict[str, Any]]:
        payload = self.get("/api/restore/targets").payload
        return payload if isinstance(payload, list) else [payload]

    def restore_validate(self, target_name: str) -> dict[str, Any]:
        return self.post("/api/restore/validate", params={"target_name": target_name}).payload

    def restore_run(self, target_name: str, *, dry_run: bool = False) -> dict[str, Any]:
        return self.post(
            "/api/restore/run",
            params={"target_name": target_name, "dry_run": str(dry_run).lower()},
        ).payload

    def restore_action(self, target_name: str, action: str, *, dry_run: bool = False) -> dict[str, Any]:
        return self.post(
            "/api/restore/action",
            json_body={
                "target_name": target_name,
                "action": action,
                "dry_run": dry_run,
            },
        ).payload

    @staticmethod
    def _decode_payload(response: httpx.Response) -> Any:
        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            try:
                return response.json()
            except ValueError:
                return {"raw": response.text}
        try:
            return response.json()
        except ValueError:
            text = response.text.strip()
            if not text:
                return {}
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}


# Backward-compat alias — preserves any existing imports of the old name.
IronClawClient = IronClawInfraClient


def build_ironclaw_client(
    base_url: str | None = None,
    *,
    timeout: float | None = None,
    headers: Mapping[str, str] | None = None,
) -> IronClawInfraClient:
    return IronClawInfraClient(base_url=base_url, timeout=timeout, headers=headers)


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT_SECONDS",
    "IronClawClient",
    "IronClawClientError",
    "IronClawHTTPStatusError",
    "IronClawInfraClient",
    "IronClawRequestError",
    "IronClawResponse",
    "build_ironclaw_client",
]
