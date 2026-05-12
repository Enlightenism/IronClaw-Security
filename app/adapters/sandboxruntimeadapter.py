from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.runtime.sandboxrouter import (
    SandboxExecutionRequest,
    SandboxExecutionResult,
    build_sandbox_router,
)

ExecutorCallable = Callable[..., Any]


@dataclass(slots=True)
class SandboxRuntimeAdapter:
    router: Any = field(default_factory=build_sandbox_router)
    executor: ExecutorCallable | None = None
    name: str = "sandboxruntimeadapter"

    def execute(
        self,
        *,
        actiontype: str,
        target: str,
        command: str | Sequence[str] | None = None,
        network_url: str | None = None,
        network_method: str = "GET",
        artifact_paths: Sequence[str] | None = None,
        content: str | bytes | None = None,
        cwd: str | None = None,
        timeout_seconds: int = 30,
        environment_scope: str = "sandbox",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = SandboxExecutionRequest(
            actiontype=actiontype,
            target=target,
            command=command,
            network_url=network_url,
            network_method=network_method,
            artifact_paths=[str(item) for item in (artifact_paths or []) if str(item).strip()],
            content=content,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment_scope=environment_scope,
            metadata={
                **dict(metadata or {}),
                "adapter": self.name,
            },
        )

        result = self.router.route(
            request=request,
            executor=self.executor,
        )
        return self._normalize_result(result=result)

    def evaluate_only(
        self,
        *,
        actiontype: str,
        target: str,
        command: str | Sequence[str] | None = None,
        network_url: str | None = None,
        network_method: str = "GET",
        artifact_paths: Sequence[str] | None = None,
        content: str | bytes | None = None,
        cwd: str | None = None,
        timeout_seconds: int = 30,
        environment_scope: str = "sandbox",
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = SandboxExecutionRequest(
            actiontype=actiontype,
            target=target,
            command=command,
            network_url=network_url,
            network_method=network_method,
            artifact_paths=[str(item) for item in (artifact_paths or []) if str(item).strip()],
            content=content,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment_scope=environment_scope,
            metadata={
                **dict(metadata or {}),
                "adapter": self.name,
                "mode": "evaluate_only",
            },
        )

        decision = self.router.evaluate(request=request)
        return decision.as_dict()

    def _normalize_result(self, *, result: SandboxExecutionResult) -> dict[str, Any]:
        payload = result.as_dict()
        payload.setdefault("adapter", self.name)
        payload.setdefault("runtime", "sandbox")
        return payload


def initialize_sandboxruntimeadapter(
    *,
    router: Any | None = None,
    executor: ExecutorCallable | None = None,
) -> SandboxRuntimeAdapter:
    return SandboxRuntimeAdapter(
        router=router or build_sandbox_router(),
        executor=executor,
    )


def build_sandboxruntimeadapter() -> SandboxRuntimeAdapter:
    return initialize_sandboxruntimeadapter()