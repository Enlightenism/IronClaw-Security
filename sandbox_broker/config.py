"""Environment-driven configuration for the host sandbox broker. No secrets are stored in code."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import math
import os
import re

BROKER_TOKEN_ENV = "SANDBOX_BROKER_TOKEN"
BROKER_BIND_HOST_ENV = "SANDBOX_BROKER_BIND_HOST"
BROKER_PORT_ENV = "SANDBOX_BROKER_PORT"
BROKER_IMAGE_ENV = "SANDBOX_BROKER_IMAGE"
BROKER_DOCKER_BINARY_ENV = "SANDBOX_BROKER_DOCKER_BINARY"
BROKER_TIMEOUT_ENV = "SANDBOX_BROKER_TIMEOUT_SECONDS"
BROKER_MAX_TIMEOUT_ENV = "SANDBOX_BROKER_MAX_TIMEOUT_SECONDS"
BROKER_MEMORY_ENV = "SANDBOX_BROKER_MEMORY"
BROKER_CPUS_ENV = "SANDBOX_BROKER_CPUS"
BROKER_PIDS_LIMIT_ENV = "SANDBOX_BROKER_PIDS_LIMIT"
BROKER_TMPFS_SIZE_ENV = "SANDBOX_BROKER_TMPFS_SIZE"
BROKER_MAX_REQUEST_BYTES_ENV = "SANDBOX_BROKER_MAX_REQUEST_BYTES"
BROKER_MAX_OUTPUT_BYTES_ENV = "SANDBOX_BROKER_MAX_OUTPUT_BYTES"
BROKER_SCANNER_IMAGE_VERSION_ENV = "SANDBOX_SCANNER_IMAGE_VERSION"
BROKER_SCANNER_IMAGE_MIN_VERSION_ENV = "SANDBOX_SCANNER_IMAGE_MIN_VERSION"
BROKER_PROMPT_GUARD_MODEL_VERSION_ENV = "SANDBOX_PROMPT_GUARD_MODEL_VERSION"
BROKER_PROMPT_GUARD_MODEL_MIN_VERSION_ENV = "SANDBOX_PROMPT_GUARD_MODEL_MIN_VERSION"

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8088
DEFAULT_IMAGE = "ironclaw-sandbox-scanner:1"
DEFAULT_DOCKER_BINARY = "docker"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_TIMEOUT_SECONDS = 60.0
DEFAULT_MEMORY = "1g"
DEFAULT_CPUS = "1.0"
DEFAULT_PIDS_LIMIT = 128
DEFAULT_TMPFS_SIZE = "64m"
DEFAULT_MAX_REQUEST_BYTES = 2_097_152
DEFAULT_MAX_OUTPUT_BYTES = 65_536
CONTAINER_USER = "65532:65532"
DEFAULT_SCANNER_IMAGE_VERSION = "1"
DEFAULT_SCANNER_IMAGE_MIN_VERSION = "1"
DEFAULT_PROMPT_GUARD_MODEL_VERSION = "86m"
DEFAULT_PROMPT_GUARD_MODEL_MIN_VERSION = "86m"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ALLOWED_ACTIONS = frozenset({"scan"})
_SIZE_PATTERN = re.compile(r"[1-9][0-9]*[bBkKmMgG]?")
_CPU_PATTERN = re.compile(r"[0-9]+(\.[0-9]+)?")
_SCANNER_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_MODEL_VERSION_PATTERN = re.compile(r"[1-9][0-9]*m")


@dataclass(frozen=True)
class BrokerConfig:
    token: str
    bind_host: str = DEFAULT_BIND_HOST
    port: int = DEFAULT_PORT
    image: str = DEFAULT_IMAGE
    docker_binary: str = DEFAULT_DOCKER_BINARY
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_timeout_seconds: float = DEFAULT_MAX_TIMEOUT_SECONDS
    memory: str = DEFAULT_MEMORY
    cpus: str = DEFAULT_CPUS
    pids_limit: int = DEFAULT_PIDS_LIMIT
    tmpfs_size: str = DEFAULT_TMPFS_SIZE
    container_user: str = CONTAINER_USER
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    allowed_actions: frozenset[str] = ALLOWED_ACTIONS
    scanner_image_version: str = DEFAULT_SCANNER_IMAGE_VERSION
    scanner_image_min_version: str = DEFAULT_SCANNER_IMAGE_MIN_VERSION
    prompt_guard_model_version: str = DEFAULT_PROMPT_GUARD_MODEL_VERSION
    prompt_guard_model_min_version: str = DEFAULT_PROMPT_GUARD_MODEL_MIN_VERSION

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> BrokerConfig:
        env = os.environ if environ is None else environ
        token = env.get(BROKER_TOKEN_ENV, "").strip()
        if not token:
            raise RuntimeError(f"{BROKER_TOKEN_ENV} must be set; the sandbox broker refuses to start without it.")

        bind_host = env.get(BROKER_BIND_HOST_ENV, DEFAULT_BIND_HOST).strip()
        if bind_host not in LOOPBACK_HOSTS:
            raise RuntimeError(f"{BROKER_BIND_HOST_ENV} must be a loopback address; the broker must not be publicly exposed.")

        timeout_seconds = _read_float(env, BROKER_TIMEOUT_ENV, DEFAULT_TIMEOUT_SECONDS, 0.1, DEFAULT_MAX_TIMEOUT_SECONDS)
        max_timeout_seconds = _read_float(env, BROKER_MAX_TIMEOUT_ENV, DEFAULT_MAX_TIMEOUT_SECONDS, 0.1, 300.0)
        if timeout_seconds > max_timeout_seconds:
            raise RuntimeError(f"{BROKER_TIMEOUT_ENV} must not exceed {BROKER_MAX_TIMEOUT_ENV}.")

        scanner_image_version = _read_version(
            env,
            BROKER_SCANNER_IMAGE_VERSION_ENV,
            DEFAULT_SCANNER_IMAGE_VERSION,
            _SCANNER_VERSION_PATTERN,
            "scanner image",
        )
        scanner_image_min_version = _read_version(
            env,
            BROKER_SCANNER_IMAGE_MIN_VERSION_ENV,
            DEFAULT_SCANNER_IMAGE_MIN_VERSION,
            _SCANNER_VERSION_PATTERN,
            "minimum scanner image",
        )
        if _version_tuple(scanner_image_version) < _version_tuple(scanner_image_min_version):
            raise RuntimeError(f"{BROKER_SCANNER_IMAGE_VERSION_ENV} must not be lower than {BROKER_SCANNER_IMAGE_MIN_VERSION_ENV}")

        prompt_guard_model_version = _read_version(
            env,
            BROKER_PROMPT_GUARD_MODEL_VERSION_ENV,
            DEFAULT_PROMPT_GUARD_MODEL_VERSION,
            _MODEL_VERSION_PATTERN,
            "Prompt Guard model",
        )
        prompt_guard_model_min_version = _read_version(
            env,
            BROKER_PROMPT_GUARD_MODEL_MIN_VERSION_ENV,
            DEFAULT_PROMPT_GUARD_MODEL_MIN_VERSION,
            _MODEL_VERSION_PATTERN,
            "minimum Prompt Guard model",
        )
        if _model_parameter_count(prompt_guard_model_version) < _model_parameter_count(prompt_guard_model_min_version):
            raise RuntimeError(f"{BROKER_PROMPT_GUARD_MODEL_VERSION_ENV} must not be lower than {BROKER_PROMPT_GUARD_MODEL_MIN_VERSION_ENV}")

        return cls(
            token=token,
            bind_host=bind_host,
            port=_read_int(env, BROKER_PORT_ENV, DEFAULT_PORT, 1, 65535),
            image=env.get(BROKER_IMAGE_ENV, "").strip() or DEFAULT_IMAGE,
            docker_binary=env.get(BROKER_DOCKER_BINARY_ENV, "").strip() or DEFAULT_DOCKER_BINARY,
            timeout_seconds=timeout_seconds,
            max_timeout_seconds=max_timeout_seconds,
            memory=_read_pattern(env, BROKER_MEMORY_ENV, DEFAULT_MEMORY, _SIZE_PATTERN),
            cpus=_read_pattern(env, BROKER_CPUS_ENV, DEFAULT_CPUS, _CPU_PATTERN),
            pids_limit=_read_int(env, BROKER_PIDS_LIMIT_ENV, DEFAULT_PIDS_LIMIT, 1, 4096),
            tmpfs_size=_read_pattern(env, BROKER_TMPFS_SIZE_ENV, DEFAULT_TMPFS_SIZE, _SIZE_PATTERN),
            max_request_bytes=_read_int(env, BROKER_MAX_REQUEST_BYTES_ENV, DEFAULT_MAX_REQUEST_BYTES, 1024, 16_777_216),
            max_output_bytes=_read_int(env, BROKER_MAX_OUTPUT_BYTES_ENV, DEFAULT_MAX_OUTPUT_BYTES, 1024, 1_048_576),
            scanner_image_version=scanner_image_version,
            scanner_image_min_version=scanner_image_min_version,
            prompt_guard_model_version=prompt_guard_model_version,
            prompt_guard_model_min_version=prompt_guard_model_min_version,
        )


def _read_int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _read_float(env: Mapping[str, str], name: str, default: float, minimum: float, maximum: float) -> float:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a number.") from exc
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _read_pattern(env: Mapping[str, str], name: str, default: str, pattern: re.Pattern[str]) -> str:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    if pattern.fullmatch(raw) is None:
        raise RuntimeError(f"{name} has an invalid format.")
    return raw


def _read_version(
    env: Mapping[str, str],
    name: str,
    default: str,
    pattern: re.Pattern[str],
    description: str,
) -> str:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    if pattern.fullmatch(raw) is None:
        raise RuntimeError(f"{name} has an invalid {description} version.")
    return raw


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _model_parameter_count(version: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)m", version, re.IGNORECASE)
    if match is None:
        raise RuntimeError("invalid Prompt Guard model version")
    return int(match.group(1))
