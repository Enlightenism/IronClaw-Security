from __future__ import annotations

import subprocess
from typing import Any

import pytest

from sandbox_broker import build_image, docker_runner
from sandbox_broker.config import BrokerConfig


def _completed(returncode: int) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=["docker"], returncode=returncode, stdout=b"", stderr=b"")


def test_build_command_uses_configured_image_and_sandbox_context() -> None:
    config = BrokerConfig(token="test-token")

    command = build_image.build_command(config)

    assert command[:4] == [config.docker_binary, "build", "-t", config.image]
    assert (build_image.BUILD_CONTEXT / "Dockerfile").is_file()
    assert command[-1] == str(build_image.BUILD_CONTEXT)


@pytest.mark.parametrize(("returncode", "expected"), [(0, "ready"), (1, "missing")])
def test_scanner_image_status_reports_inspect_result(monkeypatch: pytest.MonkeyPatch, returncode: int, expected: str) -> None:
    config = BrokerConfig(token="test-token")
    seen: list[list[str]] = []

    def _run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.append(args)
        return _completed(returncode)

    monkeypatch.setattr(docker_runner.subprocess, "run", _run)

    assert docker_runner.scanner_image_status(config) == expected
    assert seen == [[config.docker_binary, "image", "inspect", config.image]]


def test_scanner_image_status_unavailable_when_docker_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    config = BrokerConfig(token="test-token")

    def _timeout(*_args: Any, **_kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="docker", timeout=10.0)

    monkeypatch.setattr(docker_runner.subprocess, "run", _timeout)

    assert docker_runner.scanner_image_status(config) == "unavailable"
