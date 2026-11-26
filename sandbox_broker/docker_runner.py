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
    status: str = "completed"
    executor: str = "docker"
    reasons: tuple[str, ...] = ()
    risk_score: int = 0
    untrusted: bool = False
    released_text: str | None = None


def new_container_name() -> str:
    return f"{CONTAINER_NAME_PREFIX}{uuid.uuid4().hex}"


def build_docker_run_args(config: BrokerConfig, container_name: str) -> list[str]:
    return [
        config.docker_binary,
        "run",
        "--rm",
        "--pull",
        "never",
        "--init",
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


def remove_container(config: BrokerConfig, container_name: str) -> bool:
    try:
        removed = subprocess.run(
            [config.docker_binary, "rm", "-f", container_name],
            capture_output=True,
            timeout=TEARDOWN_TIMEOUT_SECONDS,
            check=False,
        )
        if removed.returncode == 0:
            return True
    except (OSError, subprocess.SubprocessError):
        return False

    try:
        inspect = subprocess.run(
            [config.docker_binary, "container", "inspect", container_name],
            capture_output=True,
            timeout=TEARDOWN_TIMEOUT_SECONDS,
            check=False,
        )
        return inspect.returncode != 0
    except (OSError, subprocess.SubprocessError):
        return False


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
    if completed.returncode != 0:
        return "missing"

    try:
        inspected = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "incomplete"
    if not isinstance(inspected, list) or not inspected:
        return "incomplete"

    record = inspected[0]
    if not isinstance(record, dict):
        return "incomplete"
    config_record = record.get("Config")
    labels = config_record.get("Labels") if isinstance(config_record, dict) else None
    if not isinstance(labels, dict):
        labels = record.get("Labels")
    if not isinstance(labels, dict):
        return "incomplete"

    scanner_version = labels.get("org.ironclaw.scanner-version")
    prompt_guard_model = labels.get("org.ironclaw.prompt-guard-model")
    fail_closed = labels.get("org.ironclaw.fail-closed")
    if not isinstance(scanner_version, str) or not isinstance(prompt_guard_model, str):
        return "incomplete"
    if fail_closed != "true":
        return "incomplete"

    try:
        from sandbox_broker.config import _version_tuple

        if _version_tuple(scanner_version) < _version_tuple(config.scanner_image_min_version):
            return "outdated"
    except (RuntimeError, ValueError):
        return "incomplete"

    model_match = prompt_guard_model.removeprefix("prompt-guard-")
    try:
        from sandbox_broker.config import _model_parameter_count

        if _model_parameter_count(model_match) < _model_parameter_count(config.prompt_guard_model_min_version):
            return "outdated"
    except RuntimeError:
        return "incomplete"

    if model_match != config.prompt_guard_model_version:
        return "outdated"
    return "ready"


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
        remove_container(config, container_name)
        return ScanResult("block", "timeout", status="blocked", executor="docker", risk_score=100, untrusted=True)
    except OSError:
        remove_container(config, container_name)
        return ScanResult("block", "docker_unavailable", status="blocked", executor="docker", risk_score=100, untrusted=True)

    teardown_verified = remove_container(config, container_name)
    if completed.returncode != 0:
        return ScanResult("block", "scanner_error", status="blocked", executor="docker", risk_score=100, untrusted=True)
    if len(completed.stdout) > config.max_output_bytes:
        return ScanResult("block", "output_too_large", status="blocked", executor="docker", risk_score=100, untrusted=True)
    if not teardown_verified:
        return ScanResult("block", "teardown_failed", status="blocked", executor="docker", risk_score=100, untrusted=True)
    result = _parse_verdict(completed.stdout)
    if result.verdict == "allow":
        return result
    return ScanResult(
        "block",
        result.reason,
        status="blocked",
        executor="docker",
        reasons=result.reasons,
        risk_score=max(result.risk_score, 70),
        untrusted=True,
    )


def _parse_verdict(stdout: bytes) -> ScanResult:
    try:
        data: Any = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
    if not isinstance(data, dict):
        return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)

    verdict = data.get("verdict")
    reason = data.get("reason")
    status = data.get("status")
    executor = data.get("executor")
    untrusted = data.get("untrusted")
    risk_score = data.get("risk_score")
    raw_reasons = data.get("reasons")
    released_text = data.get("released_text")

    if not isinstance(reason, str) or not reason.strip():
        return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
    if not isinstance(risk_score, int) or isinstance(risk_score, bool) or not 0 <= risk_score <= 100:
        return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
    if not isinstance(raw_reasons, list) or any(not isinstance(item, (str, dict)) for item in raw_reasons):
        return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)

    reasons: list[str] = []
    for item in raw_reasons:
        if isinstance(item, str):
            reasons.append(item)
        else:
            code = item.get("code")
            if not isinstance(code, str) or not code:
                return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
            reasons.append(code)

    if verdict == "allow":
        if status != "completed" or executor != "docker" or untrusted is not False:
            return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
        if risk_score > 29 or reasons:
            return ScanResult("block", "invalid_allow_result", status="blocked", executor="docker", risk_score=100, untrusted=True)
        if not isinstance(released_text, str):
            return ScanResult("block", "invalid_allow_result", status="blocked", executor="docker", risk_score=100, untrusted=True)
        return ScanResult(
            "allow",
            reason,
            status="completed",
            executor="docker",
            reasons=(),
            risk_score=risk_score,
            untrusted=False,
            released_text=released_text,
        )
    if verdict == "block":
        if status != "blocked" or executor != "docker" or untrusted is not True:
            return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
        if released_text is not None:
            return ScanResult("block", "invalid_block_result", status="blocked", executor="docker", risk_score=100, untrusted=True)
        if risk_score < 70:
            return ScanResult("block", "invalid_block_result", status="blocked", executor="docker", risk_score=100, untrusted=True)
        if not reasons:
            return ScanResult("block", "invalid_block_result", status="blocked", executor="docker", risk_score=100, untrusted=True)
        return ScanResult(
            "block",
            reason,
            status="blocked",
            executor="docker",
            reasons=tuple(reasons),
            risk_score=risk_score,
            untrusted=True,
        )
    return ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)
