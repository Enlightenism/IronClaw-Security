from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from orchestrator.policyengine import PolicyRequest, PolicyTarget, PolicyVerdict
from orchestrator.secureruntimepipeline import (
    RuntimeExecutionResult,
    SecureRuntimePipeline,
    build_runtime_request,
)


@dataclass(slots=True)
class BoundaryLimits:
    max_runtime_seconds: int = 30
    max_output_bytes: int = 50_000
    max_artifact_count: int = 10
    network_allowed: bool = False
    filesystem_allowed: bool = False
    secrets_allowed: bool = False
    allowed_paths: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_runtime_seconds": self.max_runtime_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_artifact_count": self.max_artifact_count,
            "network_allowed": self.network_allowed,
            "filesystem_allowed": self.filesystem_allowed,
            "secrets_allowed": self.secrets_allowed,
            "allowed_paths": list(self.allowed_paths),
            "allowed_hosts": list(self.allowed_hosts),
        }


@dataclass(slots=True)
class BoundaryViolation:
    code: str
    message: str
    severity: str = "high"
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "details": dict(self.details),
            "timestamp": self.timestamp,
        }


@dataclass(slots=True)
class BoundaryDecision:
    boundary_id: str
    allowed: bool
    status: str
    request_id: str
    execution_id: str | None = None
    verdict: str = "unknown"
    violations: list[BoundaryViolation] = field(default_factory=list)
    limits: dict[str, Any] = field(default_factory=dict)
    execution: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "allowed": self.allowed,
            "status": self.status,
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "verdict": self.verdict,
            "violations": [item.to_dict() for item in self.violations],
            "limits": dict(self.limits),
            "execution": dict(self.execution) if self.execution is not None else None,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }


class ExecutorBoundary:
    def __init__(
        self,
        runtime_pipeline: SecureRuntimePipeline | None = None,
        *,
        limits: BoundaryLimits | None = None,
        boundary_sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.runtime_pipeline = runtime_pipeline or SecureRuntimePipeline()
        self.limits = limits or BoundaryLimits()
        self.boundary_sink = boundary_sink

    def execute(
        self,
        request: PolicyRequest | Mapping[str, Any] | None,
        *,
        context: Mapping[str, Any] | None = None,
        limits: BoundaryLimits | Mapping[str, Any] | None = None,
    ) -> BoundaryDecision:
        normalized_request = request if isinstance(request, PolicyRequest) else PolicyRequest.from_mapping(request)
        active_limits = self._normalize_limits(limits)

        pre_violations = self._precheck_request(normalized_request, active_limits)
        if pre_violations:
            decision = self._blocked_boundary_decision(
                request_id=str((context or {}).get("request_id") or f"req-{uuid4().hex}"),
                verdict=PolicyVerdict.BLOCK.value,
                violations=pre_violations,
                active_limits=active_limits,
                metadata={
                    "phase": "precheck",
                    "action": normalized_request.action,
                    "target": normalized_request.target.value,
                },
            )
            self._emit(decision)
            return decision

        execution_result = self.runtime_pipeline.run(normalized_request, context=context)
        post_violations = self._postcheck_execution(execution_result, normalized_request, active_limits)

        if post_violations:
            decision = BoundaryDecision(
                boundary_id=f"bnd-{uuid4().hex}",
                allowed=False,
                status="blocked",
                request_id=execution_result.request_id,
                execution_id=execution_result.execution_id,
                verdict=PolicyVerdict.BLOCK.value,
                violations=post_violations,
                limits=active_limits.to_dict(),
                execution=execution_result.to_dict(),
                metadata={
                    "phase": "postcheck",
                    "execution_status": execution_result.status,
                    "action": normalized_request.action,
                    "target": normalized_request.target.value,
                },
            )
            self._emit(decision)
            return decision

        allowed = execution_result.verdict == PolicyVerdict.ALLOW.value and execution_result.allowed is True and execution_result.status == "completed"
        status = "completed" if allowed else "blocked"

        decision = BoundaryDecision(
            boundary_id=f"bnd-{uuid4().hex}",
            allowed=allowed,
            status=status,
            request_id=execution_result.request_id,
            execution_id=execution_result.execution_id,
            verdict=(PolicyVerdict.ALLOW.value if allowed else PolicyVerdict.BLOCK.value),
            violations=[],
            limits=active_limits.to_dict(),
            execution=execution_result.to_dict(),
            metadata={
                "execution_status": execution_result.status,
                "step_count": len(execution_result.steps),
                "artifact_count": len(execution_result.artifacts),
                "action": normalized_request.action,
                "target": normalized_request.target.value,
            },
        )
        self._emit(decision)
        return decision

    def execute_dict(
        self,
        request: PolicyRequest | Mapping[str, Any] | None,
        *,
        context: Mapping[str, Any] | None = None,
        limits: BoundaryLimits | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.execute(request, context=context, limits=limits).to_dict()

    def _normalize_limits(self, limits: BoundaryLimits | Mapping[str, Any] | None) -> BoundaryLimits:
        if isinstance(limits, BoundaryLimits):
            return limits
        if limits is None:
            return self.limits

        payload = dict(limits)
        return BoundaryLimits(
            max_runtime_seconds=int(payload.get("max_runtime_seconds", self.limits.max_runtime_seconds)),
            max_output_bytes=int(payload.get("max_output_bytes", self.limits.max_output_bytes)),
            max_artifact_count=int(payload.get("max_artifact_count", self.limits.max_artifact_count)),
            network_allowed=bool(payload.get("network_allowed", self.limits.network_allowed)),
            filesystem_allowed=bool(payload.get("filesystem_allowed", self.limits.filesystem_allowed)),
            secrets_allowed=bool(payload.get("secrets_allowed", self.limits.secrets_allowed)),
            allowed_paths=tuple(str(item) for item in payload.get("allowed_paths", self.limits.allowed_paths)),
            allowed_hosts=tuple(str(item) for item in payload.get("allowed_hosts", self.limits.allowed_hosts)),
        )

    def _precheck_request(self, request: PolicyRequest, limits: BoundaryLimits) -> list[BoundaryViolation]:
        violations: list[BoundaryViolation] = []

        if request.requires_network and not limits.network_allowed:
            violations.append(
                BoundaryViolation(
                    code="network_not_allowed",
                    message="Network access is outside the executor boundary.",
                    details={"requires_network": True},
                ),
            )

        if request.requires_filesystem and not limits.filesystem_allowed:
            violations.append(
                BoundaryViolation(
                    code="filesystem_not_allowed",
                    message="Filesystem access is outside the executor boundary.",
                    details={"requires_filesystem": True},
                ),
            )

        if request.requires_secrets and not limits.secrets_allowed:
            violations.append(
                BoundaryViolation(
                    code="secrets_not_allowed",
                    message="Secret handling is outside the executor boundary.",
                    details={"requires_secrets": True},
                ),
            )

        path = str(request.attributes.get("path", "")).strip()
        if path and limits.allowed_paths:
            if not any(path.lower().startswith(prefix.lower()) for prefix in limits.allowed_paths):
                violations.append(
                    BoundaryViolation(
                        code="path_outside_boundary",
                        message="Requested path is outside the allowed boundary.",
                        details={"path": path, "allowed_paths": list(limits.allowed_paths)},
                    ),
                )

        host = self._extract_host(request.attributes)
        if host and limits.allowed_hosts:
            host_normalized = host.lower()
            if not any(host_normalized == allowed.lower() or host_normalized.endswith(f".{allowed.lower()}") for allowed in limits.allowed_hosts):
                violations.append(
                    BoundaryViolation(
                        code="host_outside_boundary",
                        message="Requested host is outside the allowed network boundary.",
                        details={"host": host, "allowed_hosts": list(limits.allowed_hosts)},
                    ),
                )

        return violations

    def _postcheck_execution(
        self,
        execution_result: RuntimeExecutionResult,
        request: PolicyRequest,
        limits: BoundaryLimits,
    ) -> list[BoundaryViolation]:
        violations: list[BoundaryViolation] = []

        runtime_seconds = self._estimate_runtime_seconds(execution_result)
        if runtime_seconds > limits.max_runtime_seconds:
            violations.append(
                BoundaryViolation(
                    code="runtime_limit_exceeded",
                    message="Execution exceeded the maximum runtime boundary.",
                    details={
                        "runtime_seconds": runtime_seconds,
                        "max_runtime_seconds": limits.max_runtime_seconds,
                    },
                ),
            )

        if len(execution_result.artifacts) > limits.max_artifact_count:
            violations.append(
                BoundaryViolation(
                    code="artifact_limit_exceeded",
                    message="Execution returned too many artifacts.",
                    details={
                        "artifact_count": len(execution_result.artifacts),
                        "max_artifact_count": limits.max_artifact_count,
                    },
                ),
            )

        output_size = self._estimate_output_bytes(execution_result)
        if output_size > limits.max_output_bytes:
            violations.append(
                BoundaryViolation(
                    code="output_limit_exceeded",
                    message="Execution output exceeded the boundary size.",
                    details={
                        "output_bytes": output_size,
                        "max_output_bytes": limits.max_output_bytes,
                    },
                ),
            )

        if execution_result.verdict != PolicyVerdict.ALLOW.value or execution_result.allowed is not True or execution_result.status != "completed":
            violations.append(
                BoundaryViolation(
                    code="blocked_execution",
                    message=("Execution did not return an explicit successful allow decision from the secure runtime pipeline."),
                    severity="critical",
                    details={
                        "execution_status": execution_result.status,
                        "execution_verdict": execution_result.verdict,
                        "execution_allowed": execution_result.allowed,
                    },
                ),
            )

        if request.requires_network and not limits.network_allowed:
            violations.append(
                BoundaryViolation(
                    code="unexpected_network_request",
                    message="Execution attempted network activity outside allowed limits.",
                    details={"requires_network": True},
                ),
            )

        return self._dedupe_violations(violations)

    def _blocked_boundary_decision(
        self,
        *,
        request_id: str,
        verdict: str,
        violations: list[BoundaryViolation],
        active_limits: BoundaryLimits,
        metadata: Mapping[str, Any] | None = None,
    ) -> BoundaryDecision:
        return BoundaryDecision(
            boundary_id=f"bnd-{uuid4().hex}",
            allowed=False,
            status="blocked",
            request_id=request_id,
            execution_id=None,
            verdict=verdict,
            violations=violations,
            limits=active_limits.to_dict(),
            execution=None,
            metadata=dict(metadata or {}),
        )

    def _estimate_runtime_seconds(self, execution_result: RuntimeExecutionResult) -> int:
        if not execution_result.completed_at:
            return 0
        started = datetime.fromisoformat(execution_result.started_at)
        completed = datetime.fromisoformat(execution_result.completed_at)
        return max(int((completed - started).total_seconds()), 0)

    def _estimate_output_bytes(self, execution_result: RuntimeExecutionResult) -> int:
        total = 0
        for artifact in execution_result.artifacts:
            total += len(str(artifact.value).encode("utf-8"))
        return total

    def _extract_host(self, attributes: Mapping[str, Any]) -> str | None:
        host = attributes.get("hostname")
        if host:
            return str(host)

        url = str(attributes.get("url", "")).strip()
        if "://" not in url:
            return None

        remainder = url.split("://", 1)[1]
        host_part = remainder.split("/", 1)[0]
        return host_part.split("@", 1)[-1].split(":", 1)[0] or None

    def _dedupe_violations(self, violations: list[BoundaryViolation]) -> list[BoundaryViolation]:
        seen: set[tuple[str, str]] = set()
        ordered: list[BoundaryViolation] = []
        for violation in violations:
            key = (violation.code, violation.message)
            if key not in seen:
                seen.add(key)
                ordered.append(violation)
        return ordered

    def _emit(self, decision: BoundaryDecision) -> None:
        if self.boundary_sink is not None:
            self.boundary_sink(decision.to_dict())


def execute_with_boundary(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    context: Mapping[str, Any] | None = None,
    limits: BoundaryLimits | Mapping[str, Any] | None = None,
    boundary: ExecutorBoundary | None = None,
) -> BoundaryDecision:
    active_boundary = boundary or ExecutorBoundary()
    return active_boundary.execute(request, context=context, limits=limits)


def execute_with_boundary_dict(
    request: PolicyRequest | Mapping[str, Any] | None,
    *,
    context: Mapping[str, Any] | None = None,
    limits: BoundaryLimits | Mapping[str, Any] | None = None,
    boundary: ExecutorBoundary | None = None,
) -> dict[str, Any]:
    return execute_with_boundary(request, context=context, limits=limits, boundary=boundary).to_dict()


def build_boundary_request(
    *,
    target: PolicyTarget | str = PolicyTarget.RUNTIME,
    action: str = "execute",
    risk_score: int = 0,
    attributes: Mapping[str, Any] | None = None,
    source: str | None = None,
    actor_id: str | None = None,
    session_id: str | None = None,
    organization_id: str | None = None,
    requires_network: bool = False,
    requires_filesystem: bool = False,
    requires_secrets: bool = False,
    requires_human_review: bool = False,
    fail_closed: bool = True,
) -> PolicyRequest:
    return build_runtime_request(
        target=target,
        action=action,
        risk_score=risk_score,
        attributes=attributes,
        source=source,
        actor_id=actor_id,
        session_id=session_id,
        organization_id=organization_id,
        requires_network=requires_network,
        requires_filesystem=requires_filesystem,
        requires_secrets=requires_secrets,
        requires_human_review=requires_human_review,
        fail_closed=fail_closed,
    )


__all__ = [
    "BoundaryDecision",
    "BoundaryLimits",
    "BoundaryViolation",
    "ExecutorBoundary",
    "build_boundary_request",
    "execute_with_boundary",
    "execute_with_boundary_dict",
]
