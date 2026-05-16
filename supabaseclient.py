from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
import json
import logging
import os
from typing import Any, Union
from urllib.parse import urljoin

import httpx

logger = logging.getLogger("ironclaw.supabase")

Json = Union[None, bool, int, float, str, "JsonDict", "JsonList"]
JsonDict = dict[str, Json]
JsonList = list[Json]


class SupabaseConfigurationError(RuntimeError):
    """Raised when required Supabase configuration is missing or invalid."""


class SupabaseConnectionError(RuntimeError):
    """Raised when Supabase is unreachable or the network fails."""


class SupabaseAPIError(RuntimeError):
    """Raised when Supabase returns a non-success HTTP status code."""

    def __init__(self, status_code: int, message: str, details: Mapping[str, Any] | None = None) -> None:
        self.status_code = status_code
        self.message = message
        self.details = dict(details or {})
        super().__init__(f"Supabase API error {status_code}: {message}")


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    key: str
    service_role_key: str | None = None
    schema: str = "public"
    timeout: float = 10.0

    @classmethod
    def from_env(cls) -> SupabaseConfig:
        """Load Supabase configuration from environment variables.

        Priority:
        - SUPABASE_URL (or SUPABASEURL)
        - SUPABASE_SERVICE_ROLE_KEY if present, otherwise SUPABASE_KEY or SUPABASE_ANON_KEY
        """
        url = os.getenv("SUPABASE_URL") or os.getenv("SUPABASEURL") or ""
        service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASESERVICEROLEKEY") or None
        key = service_role_key or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASEANONKEY") or os.getenv("SUPABASE_ANON_KEY") or ""

        url = url.strip()
        key = key.strip()

        if not url or not key:
            raise SupabaseConfigurationError(
                "Supabase configuration is missing. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_KEY/SUPABASE_ANON_KEY).",
            )

        schema = (os.getenv("SUPABASE_SCHEMA") or "public").strip() or "public"
        timeout_str = (os.getenv("SUPABASE_TIMEOUT") or "").strip()
        timeout: float = 10.0
        if timeout_str:
            try:
                timeout = max(1.0, float(timeout_str))
            except ValueError:
                timeout = 10.0

        return cls(url=url, key=key, service_role_key=service_role_key, schema=schema, timeout=timeout)


class SupabaseClient:
    """Minimal Supabase HTTP client specialized for IronClaw persistence use.

    This client:
    - Uses the REST PostgREST endpoint (/{schema}/{table}) for select/insert/update/delete.
    - Exposes an RPC helper for calling Postgres functions.
    - Is synchronous; callers control threading/async boundaries.
    """

    def __init__(self, config: SupabaseConfig, client: httpx.Client | None = None) -> None:
        self._config = config
        self._base_url = config.url.rstrip("/")
        self._schema = config.schema
        self._client = client or httpx.Client(
            base_url=self._base_url,
            timeout=config.timeout,
            headers=self._build_default_headers(config),
        )

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def schema(self) -> str:
        return self._schema

    @staticmethod
    def _build_default_headers(config: SupabaseConfig) -> dict[str, str]:
        headers: dict[str, str] = {
            "apikey": config.key,
            "Authorization": f"Bearer {config.key}",
            "Content-Type": "application/json",
        }
        # Prefer service-role when available for backend-only operations
        if config.service_role_key:
            headers["Authorization"] = f"Bearer {config.service_role_key}"
        return headers

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            logger.exception("Failed to close Supabase HTTP client")

    def _handle_response(self, response: httpx.Response) -> Json:
        if 200 <= response.status_code < 300:
            if not response.content:
                return None
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    logger.exception("Supabase JSON decode error")
                    raise SupabaseAPIError(response.status_code, "Invalid JSON in Supabase response") from None
            # Fallback: return text content
            return response.text

        try:
            payload = response.json()
        except Exception:
            payload = {"body": response.text or ""}
        message = payload.get("message") or payload.get("error_description") or payload.get("error") or f"HTTP {response.status_code}"
        raise SupabaseAPIError(response.status_code, str(message), payload)

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Json | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Json:
        """Low-level request wrapper.

        - `url` may be absolute or relative to the configured Supabase URL.
        - Raises SupabaseConnectionError on network failures.
        - Raises SupabaseAPIError on non-2xx responses.
        """
        full_url = url if url.startswith("http") else urljoin(self._base_url + "/", url.lstrip("/"))
        merged_headers: MutableMapping[str, str] = dict(self._client.headers)
        if headers:
            merged_headers.update(headers)

        try:
            response = self._client.request(
                method=method.upper(),
                url=full_url,
                params=params,
                json=json_body,
                headers=merged_headers,
            )
        except httpx.RequestError as exc:
            logger.exception("Supabase request error: %s", exc)
            raise SupabaseConnectionError(f"Failed to reach Supabase: {exc}") from exc

        return self._handle_response(response)

    # ---------- Table helpers ----------

    def _table_url(self, table: str) -> str:
        # PostgREST: /rest/v1/{table} with optional schema via Prefer / headers
        return f"/rest/v1/{table}"

    def select(
        self,
        table: str,
        *,
        filters: Mapping[str, Any] | None = None,
        limit: int | None = None,
        order: tuple[str, str] | None = None,
    ) -> list[JsonDict]:
        """SELECT rows from a table.

        - filters: dict of column -> value; uses `eq.column=value` query params.
        - limit: maximum number of rows.
        - order: (column, direction) where direction is 'asc' or 'desc'.
        """
        params: dict[str, Any] = {"select": "*"}
        filters = filters or {}
        for col, value in filters.items():
            # PostgREST filter syntax: column=eq.value
            params[col] = f"eq.{value}"
        if limit is not None:
            params["limit"] = int(limit)
        if order:
            column, direction = order
            direction = direction.lower()
            if direction not in ("asc", "desc"):
                direction = "asc"
            params["order"] = f"{column}.{direction}"

        result = self.request("GET", self._table_url(table), params=params)
        if result is None:
            return []
        if isinstance(result, list):
            return [row for row in result if isinstance(row, dict)]
        if isinstance(result, dict):
            return [result]
        return []

    def insert(
        self,
        table: str,
        payload: JsonDict | list[JsonDict],
        *,
        returning: str = "representation",
    ) -> list[JsonDict]:
        """INSERT rows into a table.

        - payload: single dict or list of dicts.
        - returning: 'representation' (default) to get inserted rows back.
        """
        records: list[JsonDict]
        if isinstance(payload, list):
            records = [dict(row) for row in payload]
        else:
            records = [dict(payload)]

        headers = {"Prefer": f"return={returning}"}
        result = self.request("POST", self._table_url(table), json_body=records, headers=headers)
        if result is None:
            return []
        if isinstance(result, list):
            return [row for row in result if isinstance(row, dict)]
        if isinstance(result, dict):
            return [result]
        return []

    def update(
        self,
        table: str,
        payload: JsonDict,
        *,
        filters: Mapping[str, Any],
        returning: str = "representation",
    ) -> list[JsonDict]:
        """UPDATE rows in a table.

        - filters: dict of column -> value; all must match (AND).
        """
        if not filters:
            raise ValueError("SupabaseClient.update requires non-empty filters.")

        params: dict[str, Any] = {}
        for col, value in filters.items():
            params[col] = f"eq.{value}"

        headers = {"Prefer": f"return={returning}"}
        result = self.request("PATCH", self._table_url(table), params=params, json_body=payload, headers=headers)
        if result is None:
            return []
        if isinstance(result, list):
            return [row for row in result if isinstance(row, dict)]
        if isinstance(result, dict):
            return [result]
        return []

    def delete(self, table: str, *, filters: Mapping[str, Any]) -> list[JsonDict]:
        """DELETE rows from a table.

        - filters: dict of column -> value; all must match (AND).
        """
        if not filters:
            raise ValueError("SupabaseClient.delete requires non-empty filters.")

        params: dict[str, Any] = {}
        for col, value in filters.items():
            params[col] = f"eq.{value}"

        result = self.request("DELETE", self._table_url(table), params=params)
        if result is None:
            return []
        if isinstance(result, list):
            return [row for row in result if isinstance(row, dict)]
        if isinstance(result, dict):
            return [result]
        return []

    # ---------- RPC helper ----------

    def rpc(
        self,
        function_name: str,
        payload: Mapping[str, Any] | None = None,
        *,
        head: bool = False,
        count: str | None = None,
    ) -> Json:
        """Call a Postgres function via the RPC endpoint.

        - function_name: name of the function in the database.
        - payload: JSON body sent to the function.
        - head: if True, issue HEAD instead of POST.
        - count: if provided, sets Prefer: count=<value> (exact, planned, estimated).
        """
        url = f"/rest/v1/rpc/{function_name}"
        headers: dict[str, str] = {}
        if count:
            headers["Prefer"] = f"count={count}"

        method = "HEAD" if head else "POST"
        return self.request(method, url, json_body=payload or {}, headers=headers)


def createsupabaseclient() -> SupabaseClient:
    """Factory used by the persistence layer and repositories.

    - Validates environment configuration.
    - Returns a ready SupabaseClient instance.
    """
    config = SupabaseConfig.from_env()
    logger.info(
        "Initializing SupabaseClient",
        extra={"event": "supabase_init", "url": config.url, "schema": config.schema},
    )
    return SupabaseClient(config)


# Convenience alias used throughout the app.persistence layer
__all__ = [
    "SupabaseAPIError",
    "SupabaseClient",
    "SupabaseConfig",
    "SupabaseConfigurationError",
    "SupabaseConnectionError",
    "createsupabaseclient",
]
