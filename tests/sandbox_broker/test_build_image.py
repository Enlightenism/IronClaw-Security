from __future__ import annotations

import json
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

    assert command[:4] == [
        config.docker_binary,
        "build",
        "-f",
        str(build_image.DOCKERFILE),
    ]
    assert "--build-arg" in command
    assert f"SCANNER_VERSION={config.scanner_image_version}" in command
    assert f"PROMPT_GUARD_MODEL_VERSION={config.prompt_guard_model_version}" in command
    assert "-t" in command
    assert config.image in command
    assert build_image.DOCKERFILE.is_file()
    assert command[-1] == str(build_image.BUILD_CONTEXT)


def test_scanner_image_build_context_contains_model_and_policy_files() -> None:
    assert (build_image.BUILD_CONTEXT / "sandbox_broker" / "scanner.py").is_file()
    assert (build_image.BUILD_CONTEXT / "sandbox_broker" / "security_rules.json").is_file()
    assert (build_image.BUILD_CONTEXT / "sandbox_broker" / "policy_snapshot.json").is_file()
    assert (build_image.BUILD_CONTEXT / "models" / "prompt-guard-86m" / "model.safetensors").is_file()


def test_validate_scanner_build_bundle_succeeds() -> None:
    metadata = build_image.validate_scanner_build_bundle()

    assert metadata["scanner_version"] == "1"
    assert metadata["prompt_guard_model"] == "prompt-guard-86m"


def test_validate_scanner_build_bundle_rejects_missing_model(tmp_path) -> None:
    model_root = tmp_path / "models" / "prompt-guard-86m"
    model_root.mkdir(parents=True)

    with pytest.raises(build_image.ScannerBuildPreflightError, match="missing_required"):
        build_image.validate_scanner_build_bundle(tmp_path)


def test_validate_scanner_build_bundle_rejects_missing_policy(tmp_path) -> None:
    (tmp_path / "sandbox_broker").mkdir(parents=True)
    (tmp_path / "models" / "prompt-guard-86m").mkdir(parents=True)

    for filename in build_image.REQUIRED_MODEL_FILES:
        (tmp_path / "models" / "prompt-guard-86m" / filename).write_text(
            "{}",
            encoding="utf-8",
        )
    (tmp_path / "sandbox_broker" / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "sandbox_broker" / "scanner.py").write_text("print('ok')\n")
    (tmp_path / "sandbox_broker" / "security_rules.json").write_text(
        '{"rules":[]}',
        encoding="utf-8",
    )

    with pytest.raises(build_image.ScannerBuildPreflightError):
        build_image.validate_scanner_build_bundle(tmp_path)


def test_sync_security_rules_from_runtime_exports_runtime_rules(tmp_path) -> None:
    (tmp_path / "sandbox_broker").mkdir(parents=True)

    count = build_image.sync_security_rules_from_runtime(tmp_path)

    assert count > 0
    snapshot = json.loads((tmp_path / "sandbox_broker" / "security_rules.json").read_text(encoding="utf-8"))
    assert snapshot["rules"]


def test_scanner_image_status_reports_ready_for_complete_image(monkeypatch: pytest.MonkeyPatch) -> None:
    config = BrokerConfig(token="test-token")
    seen: list[list[str]] = []

    def _run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen.append(args)
        stdout = json.dumps(
            [
                {
                    "Config": {
                        "Labels": {
                            "org.ironclaw.scanner-version": "1",
                            "org.ironclaw.prompt-guard-model": "prompt-guard-86m",
                            "org.ironclaw.fail-closed": "true",
                        }
                    }
                }
            ]
        ).encode("utf-8")
        return subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout=stdout,
            stderr=b"",
        )

    monkeypatch.setattr(docker_runner.subprocess, "run", _run)

    assert docker_runner.scanner_image_status(config) == "ready"
    assert seen == [[config.docker_binary, "image", "inspect", config.image]]


@pytest.mark.parametrize(
    ("labels", "expected"),
    [
        ({}, "incomplete"),
        (
            {
                "org.ironclaw.scanner-version": "0",
                "org.ironclaw.prompt-guard-model": "prompt-guard-86m",
                "org.ironclaw.fail-closed": "true",
            },
            "outdated",
        ),
        (
            {
                "org.ironclaw.scanner-version": "1",
                "org.ironclaw.prompt-guard-model": "prompt-guard-22m",
                "org.ironclaw.fail-closed": "true",
            },
            "outdated",
        ),
    ],
)
def test_scanner_image_status_rejects_incomplete_or_outdated_images(
    monkeypatch: pytest.MonkeyPatch,
    labels: dict[str, str],
    expected: str,
) -> None:
    config = BrokerConfig(token="test-token")
    stdout = json.dumps([{"Config": {"Labels": labels}}]).encode("utf-8")
    monkeypatch.setattr(
        docker_runner.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout=stdout,
            stderr=b"",
        ),
    )

    assert docker_runner.scanner_image_status(config) == expected


def test_scanner_image_status_reports_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    config = BrokerConfig(token="test-token")
    monkeypatch.setattr(
        docker_runner.subprocess,
        "run",
        lambda *_args, **_kwargs: _completed(1),
    )

    assert docker_runner.scanner_image_status(config) == "missing"


def test_scanner_image_status_unavailable_when_docker_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    config = BrokerConfig(token="test-token")

    def _timeout(*_args: Any, **_kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="docker", timeout=10.0)

    monkeypatch.setattr(docker_runner.subprocess, "run", _timeout)

    assert docker_runner.scanner_image_status(config) == "unavailable"
