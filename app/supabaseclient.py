from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import requests

SUPABASE_TIMEOUT_SECONDS = 15.0


class SupabaseClientError(RuntimeError):
    pass


class SupabaseConfigurationError(SupabaseClientError):
    pass


class SupabaseConnectionError(SupabaseClientError):
    pass


class SupabaseRequestError(SupabaseClientError):
    pass


class SupabaseAPIError(SupabaseClientError):
    pass


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    key: str

    @property
    def rest_url(self) -> str:
        return f"{self.url.rstrip('/')}/rest/v1"

    @property
    def auth_url(self) -> str:
        return f"{self.url.rstrip('/')}/auth/v1"

    @property
    def storage_url(self) -> str:
        return f"{self.url.rstrip('/')}/storage/v1"

    @property
    def functions_url(self) -> str:
        return f"{self.url.rstrip('/')}/functions/v1"


def _clean_env(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip("'")
    return cleaned or None


def get_supabase_config() -> SupabaseConfig:
    url = _clean_env(
        os.getenv("SUPABASE_URL")
        or os.getenv("IRONCLAW_SUPABASE_URL")
        or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    )
    key = _clean_env(
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("IRONCLAW_SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
        or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    )

    if not url:
        raise SupabaseConfigurationError("missing SUPABASE_URL")
    if not key:
        raise SupabaseConfigurationError("missing supabase api key")
    if not url.startswith(("http://", "https://")):
        raise SupabaseConfigurationError(
            "SUPABASE_URL must start with http:// or https://"
        )

    return SupabaseConfig(url=url.rstrip("/"), key=key)


class SupabaseClient:
    def __init__(
        self,
        config: SupabaseConfig | None = None,
        *,
        timeout: float = SUPABASE_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        self.config = config or get_supabase_config()
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.session = session or requests.Session()

    @property
    def headers(self) -> dict[str, str]:
        return {
            "apikey": self.config.key,
            "Authorization": f"Bearer {self.config.key}",
            "Accept": "application/json",
        }

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        merged_headers = {**self.headers, **(headers or {})}

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                json=json,
                headers=merged_headers,
                timeout=self.timeout,
            )
        except requests.ConnectionError as exc:
            raise SupabaseConnectionError(f"connection failed: {exc}") from exc
        except requests.Timeout as exc:
            raise SupabaseConnectionError(f"request timed out: {exc}") from exc
        except requests.RequestException as exc:
            raise SupabaseRequestError(f"supabase request failed: {exc}") from exc

        if response.status_code >= 400:
            body: Any | None
            try:
                body = response.json()
            except ValueError:
                body = None

            if isinstance(body, dict):
                detail = (
                    body.get("message")
                    or body.get("error_description")
                    or body.get("error")
                    or response.text
                )
            else:
                detail = response.text

            raise SupabaseAPIError(
                f"supabase request failed with status {response.status_code}: {detail}"
            )

        if not response.content:
            return None

        content_type = response.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            return response.json()

        try:
            return response.json()
        except ValueError:
            return response.text

    def healthcheck(self) -> bool:
        self.request(
            "GET",
            self.config.rest_url,
            headers={"Accept-Profile": "public"},
        )
        return True

    def select(
        self,
        table: str,
        *,
        columns: str = "*",
        filters: dict[str, Any] | None = None,
        limit: int | None = None,
        order: str | None = None,
        ascending: bool = True,
        schema: str = "public",
    ) -> list[dict[str, Any]] | dict[str, Any]:
        if not table or not table.strip():
            raise ValueError("table is required")

        params: dict[str, Any] = {"select": columns}

        if filters:
            for key, value in filters.items():
                params[key] = value

        if limit is not None:
            if limit <= 0:
                raise ValueError("limit must be greater than zero")
            params["limit"] = str(limit)

        if order:
            params["order"] = f"{order}.{'asc' if ascending else 'desc'}"

        result = self.request(
            "GET",
            f"{self.config.rest_url}/{table}",
            params=params,
            headers={"Accept-Profile": schema},
        )

        if isinstance(result, (list, dict)):
            return result

        raise SupabaseAPIError("unexpected supabase select response shape")

    def insert(
        self,
        table: str,
        payload: dict[str, Any] | list[dict[str, Any]],
        *,
        schema: str = "public",
        returning: str = "representation",
    ) -> Any:
        if not table or not table.strip():
            raise ValueError("table is required")
        if payload is None:
            raise ValueError("payload is required")

        return self.request(
            "POST",
            f"{self.config.rest_url}/{table}",
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Prefer": f"return={returning}",
                "Content-Profile": schema,
            },
        )

    def update(
        self,
        table: str,
        payload: dict[str, Any],
        *,
        filters: dict[str, Any],
        schema: str = "public",
        returning: str = "representation",
    ) -> Any:
        if not table or not table.strip():
            raise ValueError("table is required")
        if not payload:
            raise ValueError("payload is required")
        if not filters:
            raise ValueError("filters are required")

        return self.request(
            "PATCH",
            f"{self.config.rest_url}/{table}",
            params=filters,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Prefer": f"return={returning}",
                "Content-Profile": schema,
            },
        )

    def delete(
        self,
        table: str,
        *,
        filters: dict[str, Any],
        schema: str = "public",
        returning: str = "representation",
    ) -> Any:
        if not table or not table.strip():
            raise ValueError("table is required")
        if not filters:
            raise ValueError("filters are required")

        return self.request(
            "DELETE",
            f"{self.config.rest_url}/{table}",
            params=filters,
            headers={
                "Prefer": f"return={returning}",
                "Content-Profile": schema,
            },
        )

    def rpc(
        self,
        function_name: str,
        payload: dict[str, Any] | None = None,
        *,
        schema: str = "public",
    ) -> Any:
        if not function_name or not function_name.strip():
            raise ValueError("function_name is required")

        if payload is not None:
            try:
                json.dumps(payload)
            except TypeError as exc:
                raise SupabaseClientError(
                    f"rpc payload for {function_name!r} is not JSON serializable: {exc}"
                ) from exc

        return self.request(
            "POST",
            f"{self.config.rest_url}/rpc/{function_name}",
            json=payload or {},
            headers={
                "Content-Type": "application/json",
                "Content-Profile": schema,
            },
        )


def create_supabase_client(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
    session: requests.Session | None = None,
) -> SupabaseClient:
    """Preferred factory for new SupabaseClient instances."""
    return SupabaseClient(timeout=timeout, session=session)


# Backwards-compatible alias for older call sites expecting `createsupabaseclient`.
def createsupabaseclient(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
    session: requests.Session | None = None,
) -> SupabaseClient:
    return create_supabase_client(timeout=timeout, session=session)