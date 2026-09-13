from __future__ import annotations

from collections.abc import Callable
import random
import time

import httpx

from ironclaw_sdk.exceptions import IronclawRetryExhausted, IronclawTimeoutError

_DEFAULT_RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS: int = 3
_BASE_DELAY: float = 0.5
_MAX_DELAY: float = 16.0
_SEMANTIC_TERMINAL_TOKENS: frozenset[str] = frozenset(
    {
        "pending",
        "not_active",
        "inactive",
        "invalid",
        "unsupported",
        "ownership",
        "mismatch",
        "failed",
        "cancelled",
        "does_not_match",
        "no_active_subscription",
        "install_key_requires_customer_owner_context",
        "requires_customer_owner_context",
        "unsupported platform",
        "invalid install key",
        "purchase is pending payment fulfillment",
        "purchase payment failed",
    }
)


def _parse_retry_after(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None


def _backoff_delay(attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return retry_after
    exponential = _BASE_DELAY * (2 ** (attempt - 1))
    jitter = random.uniform(0.0, exponential * 0.25)
    return min(exponential + jitter, _MAX_DELAY)


def _response_text(response: httpx.Response) -> str:
    try:
        return response.text
    except Exception:
        return ""


def _contains_terminal_state(response: httpx.Response) -> bool:
    text = _response_text(response).lower()
    if not text:
        return False

    for token in _SEMANTIC_TERMINAL_TOKENS:
        if token in text:
            return True

    try:
        payload = response.json()
    except Exception:
        return False

    def _walk(value: object) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                key_name = str(key).lower()
                if key_name in {"detail", "message", "error", "reason", "status", "payment_status", "fulfillment_status", "state"}:
                    if isinstance(nested, str) and any(token in nested.lower() for token in _SEMANTIC_TERMINAL_TOKENS):
                        return True
                if _walk(nested):
                    return True
            return False
        if isinstance(value, list):
            return any(_walk(item) for item in value)
        if isinstance(value, str):
            return any(token in value.lower() for token in _SEMANTIC_TERMINAL_TOKENS)
        return False

    return _walk(payload)


def _should_retry_response(response: httpx.Response, retryable_statuses: frozenset[int]) -> bool:
    if response.status_code not in retryable_statuses:
        return False
    return not _contains_terminal_state(response)


def execute_with_retry(
    fn: Callable[[], httpx.Response],
    retryable_statuses: frozenset[int] = _DEFAULT_RETRYABLE_STATUSES,
    max_attempts: int = _MAX_ATTEMPTS,
) -> httpx.Response:
    last_status: int | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = fn()
        except httpx.TimeoutException as exc:
            raise IronclawTimeoutError(f"Request timed out on attempt {attempt}/{max_attempts}: {exc}") from exc
        except httpx.RequestError as exc:
            if attempt == max_attempts:
                raise IronclawRetryExhausted(attempts=attempt, last_status_code=None) from exc
            delay = _backoff_delay(attempt, None)
            time.sleep(delay)
            continue

        if not _should_retry_response(response, retryable_statuses):
            return response

        last_status = response.status_code

        if attempt == max_attempts:
            break

        retry_after = _parse_retry_after(response)
        delay = _backoff_delay(attempt, retry_after)
        time.sleep(delay)

    raise IronclawRetryExhausted(attempts=max_attempts, last_status_code=last_status)


__all__ = [
    "execute_with_retry",
]
