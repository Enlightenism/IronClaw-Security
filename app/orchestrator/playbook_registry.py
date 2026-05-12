from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.orchestrator.case_file import CaseFile
from app.orchestrator.human_review_queue import ReviewDecisionRecord
from app.orchestrator.remediation_gate import GateReviewOutcome
from app.orchestrator.response_playbook import (
    PlaybookExecution,
    run_gate_outcome_playbook,
    run_review_decision_playbook,
    run_supervisor_escalation_playbook,
)
from app.orchestrator.supervisor import SupervisorEscalation

TriggerType = str
AutomationLevel = str


_SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass
class PlaybookMetrics:
    execution_count: int = 0
    completed_count: int = 0
    failed_count: int = 0
    awaiting_manual_action_count: int = 0
    last_run_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookDefinition:
    registry_id: str
    playbook_name: str
    trigger_type: TriggerType
    supported_decisions: list[str]
    min_severity: str
    max_severity: str
    automation_level: AutomationLevel
    version: str
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    rollout_notes: str = ""
    supersedes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    metrics: PlaybookMetrics = field(default_factory=PlaybookMetrics)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["metrics"] = self.metrics.to_dict()
        return payload


@dataclass
class RegistrySelection:
    selection_id: str
    registry_id: str
    playbook_name: str
    trigger_type: TriggerType
    target: str
    case_id: str
    rationale: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlaybookRegistry:
    registry_name: str
    created_at: str
    updated_at: str
    definitions: list[PlaybookDefinition] = field(default_factory=list)
    selections: list[RegistrySelection] = field(default_factory=list)
    execution_history: list[PlaybookExecution] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_name": self.registry_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "definitions": [item.to_dict() for item in self.definitions],
            "selections": [item.to_dict() for item in self.selections],
            "execution_history": [item.to_dict() for item in self.execution_history],
        }


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, -1)


def _severity_in_range(severity: str, minimum: str, maximum: str) -> bool:
    rank = _severity_rank(severity)
    return _severity_rank(minimum) <= rank <= _severity_rank(maximum)


def initialize_playbook_registry() -> PlaybookRegistry:
    now = _utcnow()
    definitions = [
        PlaybookDefinition(
            registry_id=f"pbr-{uuid4().hex[:12]}",
            playbook_name="human-review-resolution",
            trigger_type="review_decision",
            supported_decisions=["approve", "reject", "escalate", "defer"],
            min_severity="low",
            max_severity="critical",
            automation_level="hybrid",
            version="1.0.0",
            tags=["review", "analyst", "governance"],
            rollout_notes="Default response path for human review decisions.",
        ),
        PlaybookDefinition(
            registry_id=f"pbr-{uuid4().hex[:12]}",
            playbook_name="remediation-gate-resolution",
            trigger_type="gate_outcome",
            supported_decisions=["approve", "reject", "review", "escalate", "isolate"],
            min_severity="medium",
            max_severity="critical",
            automation_level="hybrid",
            version="1.0.0",
            tags=["remediation", "gate", "containment"],
            rollout_notes="Response path for remediation gate outcomes.",
        ),
        PlaybookDefinition(
            registry_id=f"pbr-{uuid4().hex[:12]}",
            playbook_name="supervisor-escalation-response",
            trigger_type="supervisor_escalation",
            supported_decisions=["medium", "high", "critical"],
            min_severity="medium",
            max_severity="critical",
            automation_level="manual-heavy",
            version="1.0.0",
            tags=["supervisor", "escalation", "priority"],
            rollout_notes="Priority escalation response with manual oversight.",
        ),
    ]
    return PlaybookRegistry(
        registry_name="ironclaw-default-playbook-registry",
        created_at=now,
        updated_at=now,
        definitions=definitions,
        selections=[],
        execution_history=[],
    )


def register_playbook(
    registry: PlaybookRegistry,
    definition: PlaybookDefinition,
) -> PlaybookRegistry:
    return PlaybookRegistry(
        registry_name=registry.registry_name,
        created_at=registry.created_at,
        updated_at=_utcnow(),
        definitions=[*registry.definitions, definition],
        selections=registry.selections,
        execution_history=registry.execution_history,
    )


def list_enabled_playbooks(
    registry: PlaybookRegistry,
    *,
    trigger_type: TriggerType | None = None,
) -> list[PlaybookDefinition]:
    items = [item for item in registry.definitions if item.enabled]
    if trigger_type is not None:
        items = [item for item in items if item.trigger_type == trigger_type]
    return items


def _update_definition_metrics(
    definitions: Iterable[PlaybookDefinition],
    *,
    registry_id: str,
    execution: PlaybookExecution,
) -> list[PlaybookDefinition]:
    updated: list[PlaybookDefinition] = []

    for definition in definitions:
        if definition.registry_id != registry_id:
            updated.append(definition)
            continue

        metrics = PlaybookMetrics(
            execution_count=definition.metrics.execution_count + 1,
            completed_count=definition.metrics.completed_count + (1 if execution.status == "completed" else 0),
            failed_count=definition.metrics.failed_count + (1 if execution.status == "failed" else 0),
            awaiting_manual_action_count=definition.metrics.awaiting_manual_action_count
            + (1 if execution.status == "awaiting_manual_action" else 0),
            last_run_at=execution.updated_at,
        )

        updated.append(
            PlaybookDefinition(
                registry_id=definition.registry_id,
                playbook_name=definition.playbook_name,
                trigger_type=definition.trigger_type,
                supported_decisions=definition.supported_decisions,
                min_severity=definition.min_severity,
                max_severity=definition.max_severity,
                automation_level=definition.automation_level,
                version=definition.version,
                enabled=definition.enabled,
                tags=definition.tags,
                rollout_notes=definition.rollout_notes,
                supersedes=definition.supersedes,
                metadata=definition.metadata,
                metrics=metrics,
            )
        )

    return updated


def _decision_value_for_selection(
    *,
    review_decision: ReviewDecisionRecord | None,
    gate_outcome: GateReviewOutcome | None,
    supervisor_escalation: SupervisorEscalation | None,
) -> str:
    if review_decision is not None:
        return review_decision.decision
    if gate_outcome is not None:
        return gate_outcome.decision
    if supervisor_escalation is not None:
        return supervisor_escalation.level
    raise ValueError("No trigger object provided.")


def _trigger_type_for_selection(
    *,
    review_decision: ReviewDecisionRecord | None,
    gate_outcome: GateReviewOutcome | None,
    supervisor_escalation: SupervisorEscalation | None,
) -> TriggerType:
    if review_decision is not None:
        return "review_decision"
    if gate_outcome is not None:
        return "gate_outcome"
    if supervisor_escalation is not None:
        return "supervisor_escalation"
    raise ValueError("No trigger object provided.")


def select_registered_playbook(
    registry: PlaybookRegistry,
    case_file: CaseFile,
    *,
    review_decision: ReviewDecisionRecord | None = None,
    gate_outcome: GateReviewOutcome | None = None,
    supervisor_escalation: SupervisorEscalation | None = None,
) -> tuple[PlaybookDefinition, RegistrySelection]:
    provided = [
        review_decision is not None,
        gate_outcome is not None,
        supervisor_escalation is not None,
    ]
    if sum(provided) != 1:
        raise ValueError("Provide exactly one trigger object.")

    trigger_type = _trigger_type_for_selection(
        review_decision=review_decision,
        gate_outcome=gate_outcome,
        supervisor_escalation=supervisor_escalation,
    )
    decision_value = _decision_value_for_selection(
        review_decision=review_decision,
        gate_outcome=gate_outcome,
        supervisor_escalation=supervisor_escalation,
    )

    candidates = [
        definition
        for definition in list_enabled_playbooks(registry, trigger_type=trigger_type)
        if decision_value in definition.supported_decisions
        and _severity_in_range(case_file.severity, definition.min_severity, definition.max_severity)
    ]

    if not candidates:
        raise LookupError(
            f"No enabled playbook matches trigger={trigger_type}, decision={decision_value}, severity={case_file.severity}."
        )

    selected = sorted(
        candidates,
        key=lambda item: (
            _severity_rank(item.max_severity) - _severity_rank(item.min_severity),
            item.automation_level != "hybrid",
            item.playbook_name,
        ),
    )[0]

    rationale = (
        f"Selected {selected.playbook_name} for trigger {trigger_type}, "
        f"decision {decision_value}, severity {case_file.severity}, "
        f"version {selected.version}."
    )

    selection = RegistrySelection(
        selection_id=f"sel-{uuid4().hex[:12]}",
        registry_id=selected.registry_id,
        playbook_name=selected.playbook_name,
        trigger_type=trigger_type,
        target=case_file.target,
        case_id=case_file.case_id,
        rationale=rationale,
    )
    return selected, selection


def execute_registered_playbook(
    registry: PlaybookRegistry,
    case_file: CaseFile,
    *,
    review_decision: ReviewDecisionRecord | None = None,
    gate_outcome: GateReviewOutcome | None = None,
    supervisor_escalation: SupervisorEscalation | None = None,
) -> tuple[PlaybookRegistry, RegistrySelection, PlaybookExecution]:
    definition, selection = select_registered_playbook(
        registry,
        case_file,
        review_decision=review_decision,
        gate_outcome=gate_outcome,
        supervisor_escalation=supervisor_escalation,
    )

    if definition.trigger_type == "review_decision":
        execution = run_review_decision_playbook(case_file, review_decision)  # type: ignore[arg-type]
    elif definition.trigger_type == "gate_outcome":
        execution = run_gate_outcome_playbook(case_file, gate_outcome)  # type: ignore[arg-type]
    else:
        execution = run_supervisor_escalation_playbook(case_file, supervisor_escalation)  # type: ignore[arg-type]

    updated_definitions = _update_definition_metrics(
        registry.definitions,
        registry_id=definition.registry_id,
        execution=execution,
    )

    updated_registry = PlaybookRegistry(
        registry_name=registry.registry_name,
        created_at=registry.created_at,
        updated_at=_utcnow(),
        definitions=updated_definitions,
        selections=[*registry.selections, selection],
        execution_history=[*registry.execution_history, execution],
    )

    return updated_registry, selection, execution


def disable_playbook(
    registry: PlaybookRegistry,
    playbook_name: str,
    *,
    version: str | None = None,
) -> PlaybookRegistry:
    updated_definitions: list[PlaybookDefinition] = []
    for definition in registry.definitions:
        should_disable = definition.playbook_name == playbook_name and (
            version is None or definition.version == version
        )

        updated_definitions.append(
            PlaybookDefinition(
                registry_id=definition.registry_id,
                playbook_name=definition.playbook_name,
                trigger_type=definition.trigger_type,
                supported_decisions=definition.supported_decisions,
                min_severity=definition.min_severity,
                max_severity=definition.max_severity,
                automation_level=definition.automation_level,
                version=definition.version,
                enabled=False if should_disable else definition.enabled,
                tags=definition.tags,
                rollout_notes=definition.rollout_notes,
                supersedes=definition.supersedes,
                metadata=definition.metadata,
                metrics=definition.metrics,
            )
        )

    return PlaybookRegistry(
        registry_name=registry.registry_name,
        created_at=registry.created_at,
        updated_at=_utcnow(),
        definitions=updated_definitions,
        selections=registry.selections,
        execution_history=registry.execution_history,
    )


def summarize_registry(registry: PlaybookRegistry) -> dict[str, Any]:
    return {
        "registry_name": registry.registry_name,
        "playbook_count": len(registry.definitions),
        "enabled_playbook_count": sum(1 for item in registry.definitions if item.enabled),
        "selection_count": len(registry.selections),
        "execution_count": len(registry.execution_history),
        "completed_execution_count": sum(
            1 for item in registry.execution_history if item.status == "completed"
        ),
        "awaiting_manual_action_count": sum(
            1 for item in registry.execution_history if item.status == "awaiting_manual_action"
        ),
        "definitions": [
            {
                "playbook_name": item.playbook_name,
                "version": item.version,
                "enabled": item.enabled,
                "metrics": item.metrics.to_dict(),
            }
            for item in registry.definitions
        ],
    }


if __name__ == "__main__":
    demo_case = CaseFile(
        case_id="case-demo",
        title="Prompt injection review",
        target="prompt://session/demo",
        status="open",
        severity="high",
        risk_score=85,
        created_at=_utcnow(),
        updated_at=_utcnow(),
        summary="Potential prompt injection requires review.",
    )

    registry = initialize_playbook_registry()
    decision = ReviewDecisionRecord(
        decision_id="rdr-demo",
        packet_id="pkt-demo",
        reviewer="analyst-1",
        decision="approve",
        rationale="Approved after controlled review.",
    )

    registry, selection, execution = execute_registered_playbook(
        registry,
        demo_case,
        review_decision=decision,
    )

    print(
        {
            "selection": selection.to_dict(),
            "execution": execution.to_dict(),
            "summary": summarize_registry(registry),
        }
    )