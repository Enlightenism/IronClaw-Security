from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.runtime.sandboxrouter import (
    ExecutorCallable,
    SandboxExecutionRequest,
    SandboxExecutionResult,
    build_sandbox_router,
)


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
        if self.executor is None:
            return self._unconfigured_payload(environment_scope=environment_scope)
        request = self._build_request(
            actiontype=actiontype,
            target=target,
            command=command,
            network_url=network_url,
            network_method=network_method,
            artifact_paths=artifact_paths,
            content=content,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment_scope=environment_scope,
            metadata=metadata,
            extra_meta={},
        )
        result = self.router.route(request=request, executor=self.executor)
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
        request = self._build_request(
            actiontype=actiontype,
            target=target,
            command=command,
            network_url=network_url,
            network_method=network_method,
            artifact_paths=artifact_paths,
            content=content,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment_scope=environment_scope,
            metadata=metadata,
            extra_meta={"mode": "evaluate_only"},
        )
        decision = self.router.evaluate(request=request)
        return decision.as_dict()

    def execute_with_decision(
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
        """Pre-evaluate, then conditionally execute. Returns both decision and result."""
        request = self._build_request(
            actiontype=actiontype,
            target=target,
            command=command,
            network_url=network_url,
            network_method=network_method,
            artifact_paths=artifact_paths,
            content=content,
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            environment_scope=environment_scope,
            metadata=metadata,
            extra_meta={},
        )
        decision = self.router.evaluate(request=request)
        decision_dict = decision.as_dict()

        if not decision.allowed:
            return {
                "executionstate": decision_dict["executionstate"],
                "verdict": decision_dict["verdict"],
                "executed": False,
                "result": None,
                "decision": decision_dict,
                "reasons": decision_dict["reasons"],
                "telemetry": {},
                "adapter": self.name,
                "runtime": environment_scope,
            }

        if self.executor is None:
            return self._unconfigured_payload(environment_scope=environment_scope, decision=decision_dict)

        result = self.router.route(request=request, executor=self.executor)
        payload = self._normalize_result(result=result)
        payload["decision"] = decision_dict
        return payload

    def _unconfigured_payload(
        self,
        *,
        environment_scope: str,
        decision: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        reasons = list((decision or {}).get("reasons", []))
        reasons.append(
            {
                "source": self.name,
                "label": "No sandbox executor",
                "details": "No sandbox executor is configured; execution denied.",
                "score": 0,
            }
        )
        return {
            "executionstate": "denied",
            "verdict": "block",
            "executed": False,
            "result": None,
            "decision": decision or {},
            "reasons": reasons,
            "telemetry": {},
            "adapter": self.name,
            "runtime": environment_scope,
        }

    def _build_request(
        self,
        *,
        actiontype: str,
        target: str,
        command: str | Sequence[str] | None,
        network_url: str | None,
        network_method: str,
        artifact_paths: Sequence[str] | None,
        content: str | bytes | None,
        cwd: str | None,
        timeout_seconds: int,
        environment_scope: str,
        metadata: Mapping[str, Any] | None,
        extra_meta: dict[str, Any],
    ) -> SandboxExecutionRequest:
        return SandboxExecutionRequest(
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
                **extra_meta,
            },
        )

    def _normalize_result(self, *, result: SandboxExecutionResult) -> dict[str, Any]:
        payload = result.as_dict()
        payload.setdefault("adapter", self.name)
        runtime = result.telemetry.get("environmentscope") or "sandbox"
        payload.setdefault("runtime", runtime)
        return payload


def initialize_sandboxruntimeadapter(
    *,
    router: Any | None = None,
    executor: ExecutorCallable | None = None,
    name: str = "sandboxruntimeadapter",
) -> SandboxRuntimeAdapter:
    return SandboxRuntimeAdapter(
        router=router or build_sandbox_router(),
        executor=executor,
        name=name,
    )


def build_sandboxruntimeadapter() -> SandboxRuntimeAdapter:
    return initialize_sandboxruntimeadapter()
