from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any

import requests

SUPABASE_TIMEOUT_SECONDS = 15.0

# ---------------------------------------------------------------------------
# Billing tier constants — single source of truth for unit pricing
# 10,000 units  → $20 USD
# 50,000 units  → $90 USD
# 100,000 units → $150 USD
# ---------------------------------------------------------------------------
BILLING_TIER_10K_UNITS: int = 10_000
BILLING_TIER_10K_PRICE_USD: int = 20

BILLING_TIER_50K_UNITS: int = 50_000
BILLING_TIER_50K_PRICE_USD: int = 90

BILLING_TIER_100K_UNITS: int = 100_000
BILLING_TIER_100K_PRICE_USD: int = 150


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
        os.getenv("SUPABASE_URL") or os.getenv("IRONCLAW_SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL"),
    )
    key = _clean_env(
        os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("IRONCLAW_SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY") or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
    )

    if not url:
        raise SupabaseConfigurationError("missing SUPABASE_URL")
    if not key:
        raise SupabaseConfigurationError("missing supabase api key")
    if not url.startswith(("http://", "https://")):
        raise SupabaseConfigurationError(
            "SUPABASE_URL must start with http:// or https://",
        )

    return SupabaseConfig(url=url.rstrip("/"), key=key)


def is_supabase_configured() -> bool:
    """Return True only when both SUPABASE_URL and a key are non-empty."""
    url = _clean_env(
        os.getenv("SUPABASE_URL") or os.getenv("IRONCLAW_SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL"),
    )
    key = _clean_env(
        os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("IRONCLAW_SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY") or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY"),
    )
    return bool(url and key and url.startswith(("http://", "https://")))


# ---------------------------------------------------------------------------
# Fluent query builder
# ---------------------------------------------------------------------------


class _QueryBuilder:
    def __init__(self, client: SupabaseClient, table: str) -> None:
        self._client = client
        self._table = table
        self._method = "GET"
        self._columns = "*"
        self._filters: list[tuple[str, str, Any]] = []
        self._in_filters: list[tuple[str, list[Any]]] = []
        self._or_filters: list[str] = []
        self._contains_filters: list[tuple[str, Any]] = []
        self._ilike_filters: list[tuple[str, str]] = []
        self._order_col: str | None = None
        self._order_desc: bool = False
        self._limit_val: int | None = None
        self._range_from: int | None = None
        self._range_to: int | None = None
        self._count_mode: str | None = None
        self._payload: Any = None
        self._returning: str = "representation"
        self._schema: str = "public"
        self._single: bool = False
        self._maybe: bool = False
        self.not_ = _NotProxy(self)

    def select(self, columns: str = "*", *, count: str | None = None) -> _QueryBuilder:
        self._method = "GET"
        self._columns = columns
        if count:
            self._count_mode = count
        return self

    def eq(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "eq", value))
        return self

    def neq(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "neq", value))
        return self

    def lt(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "lt", value))
        return self

    def lte(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "lte", value))
        return self

    def gt(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "gt", value))
        return self

    def gte(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "gte", value))
        return self

    def is_(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "is", value))
        return self

    def in_(self, column: str, values: list[Any]) -> _QueryBuilder:
        self._in_filters.append((column, values))
        return self

    def or_(self, filter_str: str) -> _QueryBuilder:
        self._or_filters.append(filter_str)
        return self

    def contains(self, column: str, value: Any) -> _QueryBuilder:
        self._contains_filters.append((column, value))
        return self

    def ilike(self, column: str, pattern: str) -> _QueryBuilder:
        self._ilike_filters.append((column, pattern))
        return self

    def not_is(self, column: str, value: Any) -> _QueryBuilder:
        self._filters.append((column, "not.is", value))
        return self

    def order(self, column: str, *, desc: bool = False) -> _QueryBuilder:
        self._order_col = column
        self._order_desc = desc
        return self

    def limit(self, value: int) -> _QueryBuilder:
        self._limit_val = value
        return self

    def range(self, from_: int, to: int) -> _QueryBuilder:
        self._range_from = from_
        self._range_to = to
        return self

    def single(self) -> _QueryBuilder:
        self._single = True
        return self

    def maybe_single(self) -> _QueryBuilder:
        self._maybe = True
        return self

    def insert(self, payload: Any, *, returning: str = "representation") -> _QueryBuilder:
        self._method = "POST"
        self._payload = payload
        self._returning = returning
        return self

    def upsert(
        self,
        payload: Any,
        *,
        on_conflict: str | None = None,
        returning: str = "representation",
    ) -> _QueryBuilder:
        self._method = "POST"
        self._payload = payload
        self._returning = returning
        if on_conflict:
            self._upsert_conflict = on_conflict
        return self

    def update(
        self,
        payload: dict[str, Any],
        *,
        returning: str = "representation",
    ) -> _QueryBuilder:
        self._method = "PATCH"
        self._payload = payload
        self._returning = returning
        return self

    def delete(self, *, returning: str = "representation") -> _QueryBuilder:
        self._method = "DELETE"
        self._returning = returning
        return self

    def _build_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {}

        if self._method == "GET":
            params["select"] = self._columns

        for col, op, val in self._filters:
            if op == "is":
                params[col] = f"is.{val}"
            elif op == "not.is":
                params[col] = f"not.is.{val}"
            else:
                params[col] = f"{op}.{val}"

        for col, values in self._in_filters:
            params[col] = "in.(" + ",".join(str(v) for v in values) + ")"

        if self._or_filters:
            params["or"] = "(" + ",".join(self._or_filters) + ")"

        for col, value in self._contains_filters:
            if isinstance(value, list):
                params[col] = "cs.{" + ",".join(str(v) for v in value) + "}"
            else:
                params[col] = f"cs.{value}"

        for col, pattern in self._ilike_filters:
            params[col] = f"ilike.{pattern}"

        if self._order_col:
            params["order"] = f"{self._order_col}.{'desc' if self._order_desc else 'asc'}"

        if self._limit_val is not None:
            params["limit"] = str(self._limit_val)

        return params

    def _build_headers(self) -> dict[str, str]:
        hdrs: dict[str, str] = {"Accept-Profile": self._schema}

        if self._method in ("POST", "PATCH", "DELETE"):
            hdrs["Content-Profile"] = self._schema
            hdrs["Prefer"] = f"return={self._returning}"
            if self._method in ("POST", "PATCH"):
                hdrs["Content-Type"] = "application/json"

        if hasattr(self, "_upsert_conflict") and self._upsert_conflict:
            hdrs["Prefer"] = f"return={self._returning},resolution=merge-duplicates"
            hdrs["on_conflict"] = self._upsert_conflict

        if self._count_mode:
            hdrs["Prefer"] = f"count={self._count_mode}"

        if self._single:
            hdrs["Accept"] = "application/vnd.pgrst.object+json"
        elif self._maybe:
            hdrs["Accept"] = "application/vnd.pgrst.object+json"
            hdrs["Prefer"] = (hdrs.get("Prefer", "") + ",missing=null").lstrip(",")

        hdrs.update(self._build_range_header())
        return hdrs

    def _build_range_header(self) -> dict[str, str]:
        if self._range_from is not None and self._range_to is not None:
            return {"Range": f"{self._range_from}-{self._range_to}"}
        return {}

    def execute(self) -> _Response:
        params = self._build_params()
        headers = self._build_headers()
        url = f"{self._client.config.rest_url}/{self._table}"

        try:
            raw = self._client.request(
                self._method,
                url,
                params=params if self._method == "GET" or self._filters or self._in_filters or self._or_filters or self._contains_filters or self._ilike_filters else None,
                json=self._payload if self._method in ("POST", "PATCH") else None,
                headers=headers,
            )
        except SupabaseAPIError as exc:
            if self._maybe and "406" in str(exc):
                return _Response(data=None, count=None)
            raise

        count: int | None = None

        if isinstance(raw, list):
            data = raw
            count = len(raw) if self._count_mode else None
        elif isinstance(raw, dict):
            data = raw
        elif raw is None:
            data = None
        else:
            data = raw

        return _Response(data=data, count=count)


class _NotProxy:
    def __init__(self, builder: _QueryBuilder) -> None:
        self._builder = builder

    def is_(self, column: str, value: Any) -> _QueryBuilder:
        return self._builder.not_is(column, value)


class _Response:
    __slots__ = ("data", "count")

    def __init__(self, data: Any, count: int | None) -> None:
        self.data = data
        self.count = count


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------


class SupabaseClient:
    def __init__(
        self,
        config: SupabaseConfig | None = None,
        *,
        timeout: float = SUPABASE_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ) -> None:
        self._config: SupabaseConfig | None = config
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.session = session or requests.Session()

    @property
    def config(self) -> SupabaseConfig:
        if self._config is None:
            self._config = get_supabase_config()
        return self._config

    @property
    def is_configured(self) -> bool:
        return is_supabase_configured()

    @property
    def headers(self) -> dict[str, str]:
        return {
            "apikey": self.config.key,
            "Authorization": f"Bearer {self.config.key}",
            "Accept": "application/json",
        }

    def table(self, table_name: str) -> _QueryBuilder:
        return _QueryBuilder(self, table_name)

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
                detail = body.get("message") or body.get("error_description") or body.get("error") or response.text
            else:
                detail = response.text

            raise SupabaseAPIError(
                f"supabase request failed with status {response.status_code}: {detail}",
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
    ) -> list[dict[str, Any]]:
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

        if isinstance(result, list):
            return result  # type: ignore[return-value]
        if isinstance(result, dict):
            return [result]  # type: ignore[return-value]

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
                    f"rpc payload for {function_name!r} is not JSON serializable: {exc}",
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
    return SupabaseClient(timeout=timeout, session=session)


def get_supabase_client(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
    session: requests.Session | None = None,
) -> SupabaseClient:
    return SupabaseClient(timeout=timeout, session=session)


def createsupabaseclient(
    *,
    timeout: float = SUPABASE_TIMEOUT_SECONDS,
    session: requests.Session | None = None,
) -> SupabaseClient:
    return create_supabase_client(timeout=timeout, session=session)


# Alias for backward compatibility
supabaseclient = get_supabase_client
