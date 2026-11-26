from __future__ import annotations

import pytest

from sandbox_broker.config import BrokerConfig


def test_model_and_scanner_versions_default_to_supported_versions() -> None:
    config = BrokerConfig(token="test-token")

    assert config.scanner_image_version == "1"
    assert config.scanner_image_min_version == "1"
    assert config.prompt_guard_model_version == "86m"
    assert config.prompt_guard_model_min_version == "86m"


def test_model_limits_are_sized_for_prompt_guard() -> None:
    config = BrokerConfig(token="test-token")

    assert config.memory == "1g"
    assert config.cpus == "1.0"
    assert config.pids_limit == 128
    assert config.tmpfs_size == "64m"
    assert config.timeout_seconds == 30.0


def test_rejects_outdated_scanner_version() -> None:
    with pytest.raises(RuntimeError, match="must not be lower"):
        BrokerConfig.from_env(
            {
                "SANDBOX_BROKER_TOKEN": "test-token",
                "SANDBOX_SCANNER_IMAGE_VERSION": "0",
                "SANDBOX_SCANNER_IMAGE_MIN_VERSION": "1",
            }
        )


def test_rejects_invalid_scanner_version() -> None:
    with pytest.raises(RuntimeError, match="invalid"):
        BrokerConfig.from_env(
            {
                "SANDBOX_BROKER_TOKEN": "test-token",
                "SANDBOX_SCANNER_IMAGE_VERSION": "latest",
            }
        )


def test_rejects_outdated_prompt_guard_model() -> None:
    with pytest.raises(RuntimeError, match="must not be lower"):
        BrokerConfig.from_env(
            {
                "SANDBOX_BROKER_TOKEN": "test-token",
                "SANDBOX_PROMPT_GUARD_MODEL_VERSION": "22m",
                "SANDBOX_PROMPT_GUARD_MODEL_MIN_VERSION": "86m",
            }
        )


def test_accepts_newer_prompt_guard_model() -> None:
    config = BrokerConfig.from_env(
        {
            "SANDBOX_BROKER_TOKEN": "test-token",
            "SANDBOX_PROMPT_GUARD_MODEL_VERSION": "86m",
            "SANDBOX_PROMPT_GUARD_MODEL_MIN_VERSION": "22m",
        }
    )

    assert config.prompt_guard_model_version == "86m"
