from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from sandbox_broker import docker_runner
from sandbox_broker.config import BrokerConfig
from sandbox_broker.docker_runner import (
    CONTAINER_NAME_PREFIX,
    build_docker_run_args,
    new_container_name,
    run_scan_container,
)

SCANNER_INPUT = b'{"target":"x"}'


def _allow_stdout(reason: str = "clean") -> bytes:
    import json

    return json.dumps(
        {
            "verdict": "allow",
            "status": "completed",
            "executor": "docker",
            "reason": reason,
            "reasons": [],
            "risk_score": 0,
            "untrusted": False,
            "released_text": "clean",
        }
    ).encode("utf-8")


def _block_stdout(reason: str = "suspicious_content") -> bytes:
    import json

    return json.dumps(
        {
            "verdict": "block",
            "status": "blocked",
            "executor": "docker",
            "reason": reason,
            "reasons": [{"code": reason, "category": "security", "severity": "critical", "detail": reason}],
            "risk_score": 100,
            "untrusted": True,
            "released_text": None,
        }
    ).encode("utf-8")


class _DockerRecorder:
    def __init__(self, result: subprocess.CompletedProcess[bytes] | None = None, exc: BaseException | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self._result = result
        self._exc = exc

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((args, kwargs))
        if self._exc is not None:
            raise self._exc
        assert self._result is not None
        return self._result


def _completed(stdout: bytes = b"", returncode: int = 0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=["docker"], returncode=returncode, stdout=stdout, stderr=b"")


def _flag_value(args: list[str], flag: str) -> str:
    return args[args.index(flag) + 1]


def _scan_name(recorder: _DockerRecorder) -> str:
    return _flag_value(recorder.calls[0][0], "--name")


def _assert_torn_down(recorder: _DockerRecorder, name: str) -> None:
    teardown_calls = [call for call in recorder.calls if len(call[0]) >= 4 and call[0][1:3] == ["rm", "-f"]]
    assert teardown_calls
    teardown_args, teardown_kwargs = teardown_calls[-1]
    assert teardown_args == [BrokerConfig(token="t").docker_binary, "rm", "-f", name]
    assert teardown_kwargs["timeout"] == docker_runner.TEARDOWN_TIMEOUT_SECONDS


@pytest.fixture
def config() -> BrokerConfig:
    return BrokerConfig(token="test-token")


def test_run_args_apply_hardening_flags(config: BrokerConfig) -> None:
    args = build_docker_run_args(config, "ironclaw-scan-abc")

    assert args[0] == config.docker_binary
    assert args[1] == "run"
    assert "--rm" in args
    assert _flag_value(args, "--pull") == "never"
    assert "--init" in args
    assert "-i" in args
    assert _flag_value(args, "--name") == "ironclaw-scan-abc"
    assert _flag_value(args, "--network") == "none"
    assert "--read-only" in args
    assert _flag_value(args, "--cap-drop") == "ALL"
    assert _flag_value(args, "--security-opt") == "no-new-privileges:true"
    assert _flag_value(args, "--memory") == config.memory
    assert _flag_value(args, "--memory-swap") == config.memory
    assert _flag_value(args, "--cpus") == config.cpus
    assert _flag_value(args, "--pids-limit") == str(config.pids_limit)
    assert _flag_value(args, "--tmpfs").startswith("/tmp:rw,noexec,nosuid,nodev,size=")
    assert _flag_value(args, "--user") == "65532:65532"
    assert args[-1] == config.image


def test_container_names_are_unique_and_prefixed() -> None:
    first = new_container_name()
    second = new_container_name()

    assert first.startswith(CONTAINER_NAME_PREFIX)
    assert second.startswith(CONTAINER_NAME_PREFIX)
    assert first != second


def test_allow_verdict_passes_through_and_container_is_destroyed(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(result=_completed(_allow_stdout()))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    result = run_scan_container(config, SCANNER_INPUT, 5.0)

    assert result == docker_runner.ScanResult(
        "allow",
        "clean",
        released_text="clean",
    )
    _, scan_kwargs = recorder.calls[0]
    assert scan_kwargs["input"] == SCANNER_INPUT
    assert scan_kwargs["timeout"] == 5.0
    _assert_torn_down(recorder, _scan_name(recorder))


def test_block_verdict_passes_through(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(result=_completed(_block_stdout()))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    result = run_scan_container(config, SCANNER_INPUT, 5.0)

    assert result == docker_runner.ScanResult(
        "block",
        "suspicious_content",
        status="blocked",
        executor="docker",
        reasons=("suspicious_content",),
        risk_score=100,
        untrusted=True,
    )
    _assert_torn_down(recorder, _scan_name(recorder))


def test_timeout_blocks_and_destroys_container(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(exc=subprocess.TimeoutExpired(cmd="docker", timeout=5.0))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    result = run_scan_container(config, SCANNER_INPUT, 5.0)

    assert result == docker_runner.ScanResult("block", "timeout", status="blocked", executor="docker", risk_score=100, untrusted=True)
    _assert_torn_down(recorder, _scan_name(recorder))


def test_nonzero_exit_blocks_and_destroys_container(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(result=_completed(b"", returncode=1))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    result = run_scan_container(config, SCANNER_INPUT, 5.0)

    assert result == docker_runner.ScanResult("block", "scanner_error", status="blocked", executor="docker", risk_score=100, untrusted=True)
    _assert_torn_down(recorder, _scan_name(recorder))


def test_missing_docker_binary_blocks_and_still_attempts_teardown(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(exc=FileNotFoundError("docker"))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    result = run_scan_container(config, SCANNER_INPUT, 5.0)

    assert result == docker_runner.ScanResult("block", "docker_unavailable", status="blocked", executor="docker", risk_score=100, untrusted=True)
    _assert_torn_down(recorder, _scan_name(recorder))


def test_invalid_json_blocks(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(result=_completed(b"not json"))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    assert run_scan_container(config, SCANNER_INPUT, 5.0) == docker_runner.ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)


@pytest.mark.parametrize("stdout", [b"[]", b'{"verdict":"maybe"}', b"\xff\xfe"])
def test_unexpected_output_shape_blocks(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig, stdout: bytes) -> None:
    recorder = _DockerRecorder(result=_completed(stdout))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    assert run_scan_container(config, SCANNER_INPUT, 5.0) == docker_runner.ScanResult("block", "invalid_output", status="blocked", executor="docker", risk_score=100, untrusted=True)


def test_block_without_structured_reasons_blocks(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    stdout = json.dumps(
        {
            "verdict": "block",
            "status": "blocked",
            "executor": "docker",
            "reason": "pattern_match",
            "reasons": [],
            "risk_score": 100,
            "untrusted": True,
        }
    ).encode("utf-8")
    recorder = _DockerRecorder(result=_completed(stdout))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    assert run_scan_container(config, SCANNER_INPUT, 5.0) == docker_runner.ScanResult(
        "block",
        "invalid_block_result",
        status="blocked",
        executor="docker",
        risk_score=100,
        untrusted=True,
    )


def test_oversized_output_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    small_config = BrokerConfig(token="test-token", max_output_bytes=1024)
    recorder = _DockerRecorder(result=_completed(b"x" * 1025))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    assert run_scan_container(small_config, SCANNER_INPUT, 5.0) == docker_runner.ScanResult("block", "output_too_large", status="blocked", executor="docker", risk_score=100, untrusted=True)
    _assert_torn_down(recorder, _scan_name(recorder))


def test_teardown_failure_blocks(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(result=_completed(_allow_stdout()))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)
    monkeypatch.setattr(docker_runner, "remove_container", lambda *_args: False)

    result = run_scan_container(config, SCANNER_INPUT, 5.0)

    assert result == docker_runner.ScanResult(
        "block",
        "teardown_failed",
        status="blocked",
        executor="docker",
        risk_score=100,
        untrusted=True,
    )


def test_each_return_gets_a_fresh_container_name(monkeypatch: pytest.MonkeyPatch, config: BrokerConfig) -> None:
    recorder = _DockerRecorder(result=_completed(_allow_stdout()))
    monkeypatch.setattr(docker_runner.subprocess, "run", recorder)

    run_scan_container(config, SCANNER_INPUT, 5.0)
    run_scan_container(config, SCANNER_INPUT, 5.0)

    first_name = _flag_value(recorder.calls[0][0], "--name")
    second_name = _flag_value(recorder.calls[2][0], "--name")
    assert first_name != second_name
