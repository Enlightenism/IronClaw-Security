"""Builds the scanner image that the sandbox broker runs for every return.

Run from the repository root on the broker host:
    python -m sandbox_broker.build_image
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from sandbox_broker.config import BrokerConfig

BUILD_CONTEXT = Path(__file__).resolve().parent


def build_command(config: BrokerConfig) -> list[str]:
    return [config.docker_binary, "build", "-t", config.image, str(BUILD_CONTEXT)]


def main() -> int:
    config = BrokerConfig.from_env()
    completed = subprocess.run(build_command(config), check=False)
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
