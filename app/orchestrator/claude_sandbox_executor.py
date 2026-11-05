from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.services.sandbox_broker_client import SandboxBrokerClient


@runtime_checkable
class SandboxRunner(Protocol):
    """Minimal protocol for a sandbox runner.

    A concrete implementation could:
      - talk to a firecracker/microVM pool,
      - use containerized sandboxes,
      - or isolate via a dedicated constrained worker process.
    """

    def run(
        self,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
        read_only_fs: bool = True,
        network_enabled: bool = False,
    ) -> dict[str, Any]: ...


class DockerSandboxRunner:
    """Runs actions in a fresh, locked-down container via the host sandbox broker.

    Delegates to SandboxBrokerClient, which fails closed on any transport,
    broker, timeout, or malformed-reply error.
    """

    def __init__(self, broker_url: str | None = None, broker_token: str | None = None) -> None:
        self._client = SandboxBrokerClient(broker_url=broker_url, broker_token=broker_token)

    def run(
        self,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
        read_only_fs: bool = True,
        network_enabled: bool = False,
    ) -> dict[str, Any]:
        return self._client.run(
            action_type,
            target,
            payload,
            timeout_seconds=timeout_seconds,
            read_only_fs=read_only_fs,
            network_enabled=network_enabled,
        )
