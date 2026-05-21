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

        if response.status_code not in retryable_statuses:
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
