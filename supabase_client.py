from __future__ import annotations

import os
from typing import Any

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException, Timeout
from urllib3.util.retry import Retry

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

REST_BASE = f"{SUPABASE_URL}/rest/v1"
DEFAULT_TIMEOUT = 10


class SupabaseClientError(Exception):
    pass


class SupabaseConnectionError(SupabaseClientError):
    pass


class SupabaseAPIError(SupabaseClientError):
    pass


def _build_session() -> Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PATCH"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


SESSION = _build_session()


def _headers(prefer: str = "return=minimal") -> dict[str, str]:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": prefer,
    }


def _handle_response(response: Response) -> Any:
    try:
        response.raise_for_status()
    except RequestException as exc:
        body = response.text.strip()
        detail = f"Supabase HTTP {response.status_code}"
        if body:
            detail = f"{detail}: {body}"
        raise SupabaseAPIError(detail) from exc

    if not response.content:
        return None

    try:
        return response.json()
    except ValueError as exc:
        raise SupabaseAPIError("Supabase returned a non-JSON response.") from exc


def _request(
    method: str,
    path: str,
    *,
    json_body: Any | None = None,
    params: dict[str, Any] | None = None,
    prefer: str = "return=minimal",
    timeout: int = DEFAULT_TIMEOUT,
) -> Any:
    url = f"{REST_BASE}/{path.lstrip('/')}"

    try:
        response = SESSION.request(
            method=method.upper(),
            url=url,
            json=json_body,
            params=params,
            headers=_headers(prefer=prefer),
            timeout=timeout,
        )
    except Timeout as exc:
        raise SupabaseConnectionError(
            f"Request to {url} timed out after {timeout} seconds."
        ) from exc
    except RequestException as exc:
        raise SupabaseConnectionError(f"Could not connect to {url}: {exc}") from exc

    return _handle_response(response)


def healthcheck() -> dict[str, Any]:
    _request(
        "GET",
        "",
        prefer="return=representation",
    )
    return {
        "status": "ok",
        "service": "supabase",
        "rest_base": REST_BASE,
        "reachable": True,
    }