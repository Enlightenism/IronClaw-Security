from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Final

_DEFAULT_BASE_URL: Final[str] = "http://localhost:8000"
_DEFAULT_TIMEOUT: Final[float] = 10.0
_MIN_TIMEOUT: Final[float] = 1.0
_MAX_TIMEOUT: Final[float] = 120.0


@dataclass(frozen=True)
class CLIConfig:
    api_key: str
    base_url: str
    timeout_seconds: float


def load_cli_config() -> CLIConfig:
    api_key = os.environ.get("IRONCLAW_API_KEY", "").strip()
    if not api_key:
        raise OSError("IRONCLAW_API_KEY is required but not set. Export it as an environment variable before running the CLI.")

    base_url = os.environ.get("IRONCLAW_BASE_URL", _DEFAULT_BASE_URL).strip().rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise OSError(f"IRONCLAW_BASE_URL must start with http:// or https://, got: {base_url!r}")

    raw_timeout = os.environ.get("IRONCLAW_TIMEOUT_SECONDS", "").strip()
    if raw_timeout:
        try:
            timeout_seconds = float(raw_timeout)
        except ValueError as exc:
            raise OSError(f"IRONCLAW_TIMEOUT_SECONDS must be a number, got: {raw_timeout!r}") from exc
        if not (_MIN_TIMEOUT <= timeout_seconds <= _MAX_TIMEOUT):
            raise OSError(f"IRONCLAW_TIMEOUT_SECONDS must be between {_MIN_TIMEOUT} and {_MAX_TIMEOUT}, got: {timeout_seconds}")
    else:
        timeout_seconds = _DEFAULT_TIMEOUT

    return CLIConfig(
        api_key=api_key,
        base_url=base_url,
        timeout_seconds=timeout_seconds,
    )


__all__ = [
    "CLIConfig",
    "load_cli_config",
]
