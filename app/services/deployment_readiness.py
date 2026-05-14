from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ReadinessLevel(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class DeploymentReadinessInput:
    compatibility_state: str
    telemetry_state: str
    lifecycle_state: str
    rollout_recommendation: str
    risk_score: float
    has_open_blockers: bool = False
    has_audit_gaps: bool = False
    has_rollback_plan: bool = True
    has_test_evidence: bool = True
    requires_manual_review: bool = False
    manual_review_completed: bool = False


@dataclass(frozen=True)
class ReadinessFinding:
    key: str
    level: ReadinessLevel
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "level": self.level.value,
            "message": self.message,
        }


@dataclass(frozen=True)
class DeploymentReadinessResult:
    level: ReadinessLevel
    ready: bool
    score: float
    findings: list[ReadinessFinding] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level.value,
            "ready": self.ready,
            "score": self.score,
            "findings": [finding.to_dict() for finding in self.findings],
            "next_actions": list(self.next_actions),
        }


def evaluate_deployment_readiness(
    readiness_input: DeploymentReadinessInput,
) -> DeploymentReadinessResult:
    findings: list[ReadinessFinding] = []
    next_actions: list[str] = []

    findings.extend(_evaluate_compatibility(readiness_input))
    findings.extend(_evaluate_telemetry(readiness_input))
    findings.extend(_evaluate_lifecycle(readiness_input))
    findings.extend(_evaluate_rollout(readiness_input))
    findings.extend(_evaluate_controls(readiness_input))

    level = _derive_level(findings)
    ready = level == ReadinessLevel.PASS
    score = _calculate_readiness_score(readiness_input, findings)

    for finding in findings:
        if finding.level == ReadinessLevel.FAIL:
            next_actions.append(f"Resolve failure: {finding.message}")
        elif finding.level == ReadinessLevel.WARN:
            next_actions.append(f"Review warning: {finding.message}")

    next_actions = _deduplicate(next_actions)

    return DeploymentReadinessResult(
        level=level,
        ready=ready,
        score=score,
        findings=findings,
        next_actions=next_actions,
    )


def summarize_deployment_readiness(
    result: DeploymentReadinessResult,
) -> dict[str, object]:
    return result.to_dict()


def _evaluate_compatibility(
    readiness_input: DeploymentReadinessInput,
) -> list[ReadinessFinding]:
    state = readiness_input.compatibility_state
    if state == "unsupported":
        return [
            ReadinessFinding(
                key="compatibility",
                level=ReadinessLevel.FAIL,
                message="Compatibility state is unsupported.",
            ),
        ]
    if state == "warning":
        return [
            ReadinessFinding(
                key="compatibility",
                level=ReadinessLevel.WARN,
                message="Compatibility state contains warnings.",
            ),
        ]
    return [
        ReadinessFinding(
            key="compatibility",
            level=ReadinessLevel.PASS,
            message="Compatibility checks passed.",
        ),
    ]


def _evaluate_telemetry(
    readiness_input: DeploymentReadinessInput,
) -> list[ReadinessFinding]:
    state = readiness_input.telemetry_state
    if state == "unsupported":
        return [
            ReadinessFinding(
                key="telemetry",
                level=ReadinessLevel.FAIL,
                message="Telemetry health is unsupported.",
            ),
        ]
    if state == "warning":
        return [
            ReadinessFinding(
                key="telemetry",
                level=ReadinessLevel.WARN,
                message="Telemetry health contains warnings.",
            ),
        ]
    return [
        ReadinessFinding(
            key="telemetry",
            level=ReadinessLevel.PASS,
            message="Telemetry health is supported.",
        ),
    ]


def _evaluate_lifecycle(
    readiness_input: DeploymentReadinessInput,
) -> list[ReadinessFinding]:
    state = readiness_input.lifecycle_state
    if state == "blocked":
        return [
            ReadinessFinding(
                key="lifecycle",
                level=ReadinessLevel.FAIL,
                message="Lifecycle state is blocked.",
            ),
        ]
    if state == "degraded":
        return [
            ReadinessFinding(
                key="lifecycle",
                level=ReadinessLevel.WARN,
                message="Lifecycle state is degraded.",
            ),
        ]
    if state == "retired":
        return [
            ReadinessFinding(
                key="lifecycle",
                level=ReadinessLevel.FAIL,
                message="Lifecycle state is retired.",
            ),
        ]
    if state == "draft":
        return [
            ReadinessFinding(
                key="lifecycle",
                level=ReadinessLevel.WARN,
                message="Lifecycle state is still draft.",
            ),
        ]
    return [
        ReadinessFinding(
            key="lifecycle",
            level=ReadinessLevel.PASS,
            message="Lifecycle state is active.",
        ),
    ]


def _evaluate_rollout(
    readiness_input: DeploymentReadinessInput,
) -> list[ReadinessFinding]:
    recommendation = readiness_input.rollout_recommendation
    if recommendation == "hold":
        return [
            ReadinessFinding(
                key="rollout",
                level=ReadinessLevel.FAIL,
                message="Rollout recommendation is hold.",
            ),
        ]
    if recommendation == "rollback_ready":
        return [
            ReadinessFinding(
                key="rollout",
                level=ReadinessLevel.WARN,
                message="Rollout requires rollback-ready posture.",
            ),
        ]
    if recommendation == "limited_rollout":
        return [
            ReadinessFinding(
                key="rollout",
                level=ReadinessLevel.WARN,
                message="Rollout recommendation is limited rollout.",
            ),
        ]
    return [
        ReadinessFinding(
            key="rollout",
            level=ReadinessLevel.PASS,
            message="Rollout recommendation allows release.",
        ),
    ]


def _evaluate_controls(
    readiness_input: DeploymentReadinessInput,
) -> list[ReadinessFinding]:
    findings: list[ReadinessFinding] = []

    if readiness_input.has_open_blockers:
        findings.append(
            ReadinessFinding(
                key="open_blockers",
                level=ReadinessLevel.FAIL,
                message="Open blockers remain unresolved.",
            ),
        )
    else:
        findings.append(
            ReadinessFinding(
                key="open_blockers",
                level=ReadinessLevel.PASS,
                message="No open blockers remain.",
            ),
        )

    if readiness_input.has_audit_gaps:
        findings.append(
            ReadinessFinding(
                key="audit_gaps",
                level=ReadinessLevel.WARN,
                message="Audit coverage is incomplete.",
            ),
        )
    else:
        findings.append(
            ReadinessFinding(
                key="audit_gaps",
                level=ReadinessLevel.PASS,
                message="Audit coverage is complete.",
            ),
        )

    if readiness_input.has_rollback_plan:
        findings.append(
            ReadinessFinding(
                key="rollback_plan",
                level=ReadinessLevel.PASS,
                message="Rollback plan is available.",
            ),
        )
    else:
        findings.append(
            ReadinessFinding(
                key="rollback_plan",
                level=ReadinessLevel.FAIL,
                message="Rollback plan is missing.",
            ),
        )

    if readiness_input.has_test_evidence:
        findings.append(
            ReadinessFinding(
                key="test_evidence",
                level=ReadinessLevel.PASS,
                message="Test evidence is available.",
            ),
        )
    else:
        findings.append(
            ReadinessFinding(
                key="test_evidence",
                level=ReadinessLevel.FAIL,
                message="Test evidence is missing.",
            ),
        )

    if readiness_input.requires_manual_review and not readiness_input.manual_review_completed:
        findings.append(
            ReadinessFinding(
                key="manual_review",
                level=ReadinessLevel.FAIL,
                message="Manual review is required but not completed.",
            ),
        )
    elif readiness_input.requires_manual_review and readiness_input.manual_review_completed:
        findings.append(
            ReadinessFinding(
                key="manual_review",
                level=ReadinessLevel.PASS,
                message="Required manual review is complete.",
            ),
        )

    return findings


def _derive_level(findings: list[ReadinessFinding]) -> ReadinessLevel:
    if any(finding.level == ReadinessLevel.FAIL for finding in findings):
        return ReadinessLevel.FAIL
    if any(finding.level == ReadinessLevel.WARN for finding in findings):
        return ReadinessLevel.WARN
    return ReadinessLevel.PASS


def _calculate_readiness_score(
    readiness_input: DeploymentReadinessInput,
    findings: list[ReadinessFinding],
) -> float:
    score = min(max(readiness_input.risk_score, 0.0), 100.0)

    for finding in findings:
        if finding.level == ReadinessLevel.FAIL:
            score -= 20.0
        elif finding.level == ReadinessLevel.WARN:
            score -= 8.0

    return max(0.0, min(100.0, score))


def _deduplicate(items: list[str]) -> list[str]:
    seen = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result
