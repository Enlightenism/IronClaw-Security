"""Builds and runs one locked-down scanner container per return, then destroys it."""

from __future__ import annotations

from dataclasses import dataclass
import json
import subprocess
from typing import Any
import uuid

from sandbox_broker.config import BrokerConfig

CONTAINER_NAME_PREFIX = "ironclaw-scan-"
TEARDOWN_TIMEOUT_SECONDS = 15.0
IMAGE_CHECK_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class ScanResult:
    verdict: str
    reason: str


def new_container_name() -> str:
    return f"{CONTAINER_NAME_PREFIX}{uuid.uuid4().hex}"


def build_docker_run_args(config: BrokerConfig, container_name: str) -> list[str]:
    return [
        config.docker_binary,
        "run",
        "--rm",
        "-i",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        config.memory,
        "--memory-swap",
        config.memory,
        "--cpus",
        config.cpus,
        "--pids-limit",
        str(config.pids_limit),
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={config.tmpfs_size}",
        "--user",
        config.container_user,
        config.image,
    ]


def remove_container(config: BrokerConfig, container_name: str) -> None:
    try:
        subprocess.run(
            [config.docker_binary, "rm", "-f", container_name],
            capture_output=True,
            timeout=TEARDOWN_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return


def scanner_image_status(config: BrokerConfig) -> str:
    try:
        completed = subprocess.run(
            [config.docker_binary, "image", "inspect", config.image],
            capture_output=True,
            timeout=IMAGE_CHECK_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return "ready" if completed.returncode == 0 else "missing"


def run_scan_container(config: BrokerConfig, scanner_input: bytes, timeout_seconds: float) -> ScanResult:
    container_name = new_container_name()
    try:
        completed = subprocess.run(
            build_docker_run_args(config, container_name),
            input=scanner_input,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ScanResult("block", "timeout")
    except OSError:
        return ScanResult("block", "docker_unavailable")
    finally:
        remove_container(config, container_name)

    if completed.returncode != 0:
        return ScanResult("block", "scanner_error")
    if len(completed.stdout) > config.max_output_bytes:
        return ScanResult("block", "output_too_large")
    return _parse_verdict(completed.stdout)


def _parse_verdict(stdout: bytes) -> ScanResult:
    try:
        data: Any = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return ScanResult("block", "invalid_output")
    if not isinstance(data, dict):
        return ScanResult("block", "invalid_output")
    verdict = data.get("verdict")
    reason = data.get("reason")
    if verdict == "allow":
        return ScanResult("allow", str(reason or "clean"))
    if verdict == "block":
        return ScanResult("block", str(reason or "suspicious_content"))
    return ScanResult("block", "invalid_output")
