from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    list_integrations,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


def _normalize_status(value: str | None) -> str:
    if not value:
        return "unknown"
    return value.strip().lower()


def _runbook_state(
    *,
    status: str,
    verified: bool,
    has_command: bool,
    has_install_target: bool,
) -> str:
    normalized = _normalize_status(status)
    if normalized in {"disabled", "inactive", "retired"}:
        return "retired"
    if normalized in {"planned", "draft"}:
        return "draft"
    if verified and has_command and has_install_target:
        return "ready"
    if verified or has_command or has_install_target:
        return "partial"
    return "missing"


def _runbook_score(
    *,
    verified: bool,
    has_command: bool,
    has_install_target: bool,
    pass_count: int,
    warn_count: int,
    fail_count: int,
) -> int:
    score = 0
    if verified:
        score += 35
    if has_command:
        score += 25
    if has_install_target:
        score += 20
    score += min(pass_count * 2, 20)
    score -= min(warn_count * 2, 10)
    score -= min(fail_count * 15, 45)
    return max(0, min(score, 100))


@dataclass(slots=True)
class IntegrationRunbookStep:
    key: str
    title: str
    completed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "completed": self.completed,
            "detail": self.detail,
        }


@dataclass(slots=True)
class IntegrationRunbookItem:
    integration_id: str
    slug: str
    name: str
    platform: str
    status: str
    runbook_state: str
    runbook_score: int
    checked_at: str
    steps: list[IntegrationRunbookStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform,
            "status": self.status,
            "runbook_state": self.runbook_state,
            "runbook_score": self.runbook_score,
            "checked_at": self.checked_at,
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationRunbooksView:
    title: str
    total: int
    ready_count: int
    partial_count: int
    missing_count: int
    items: list[IntegrationRunbookItem] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "total": self.total,
            "ready_count": self.ready_count,
            "partial_count": self.partial_count,
            "missing_count": self.missing_count,
            "items": [item.to_dict() for item in self.items],
            "metadata": dict(self.metadata),
        }


def build_integration_runbooks_view(
    *,
    registry: IntegrationRegistry,
    requested_by: str = "ui-runbooks",
) -> IntegrationRunbooksView:
    records = list_integrations(registry)

    items: list[IntegrationRunbookItem] = []
    ready_count = 0
    partial_count = 0
    missing_count = 0

    for record in records:
        verification = verify_integration(
            registry,
            record.integration_id,
            strict=False,
            requested_by=requested_by,
        )
        summary = summarize_verification_result(verification)

        verified = bool(summary.get("verified", False))
        pass_count = int(summary.get("pass_count", 0))
        warn_count = int(summary.get("warn_count", 0))
        fail_count = int(summary.get("fail_count", 0))
        checked_at = str(summary.get("checked_at", ""))

        has_command = bool(getattr(record, "command_name", None))
        has_install_target = bool(getattr(record, "install_target", None))

        runbook_state = _runbook_state(
            status=getattr(record, "status", "unknown"),
            verified=verified,
            has_command=has_command,
            has_install_target=has_install_target,
        )
        runbook_score = _runbook_score(
            verified=verified,
            has_command=has_command,
            has_install_target=has_install_target,
            pass_count=pass_count,
            warn_count=warn_count,
            fail_count=fail_count,
        )

        if runbook_state == "ready":
            ready_count += 1
        elif runbook_state in {"partial", "draft"}:
            partial_count += 1
        else:
            missing_count += 1

        steps = [
            IntegrationRunbookStep(
                key="registered",
                title="Registered",
                completed=True,
                detail=f"{record.name} is present in the integration registry.",
            ),
            IntegrationRunbookStep(
                key="verified",
                title="Verification",
                completed=verified,
                detail=(f"Verification summary: {pass_count} pass, {warn_count} warn, {fail_count} fail."),
            ),
            IntegrationRunbookStep(
                key="command",
                title="Command Ready",
                completed=has_command,
                detail=(f"Command available: {getattr(record, 'command_name', None) or 'not configured'}."),
            ),
            IntegrationRunbookStep(
                key="install_target",
                title="Install Target",
                completed=has_install_target,
                detail=(f"Install target: {getattr(record, 'install_target', None) or 'not configured'}."),
            ),
        ]

        items.append(
            IntegrationRunbookItem(
                integration_id=record.integration_id,
                slug=record.slug,
                name=record.name,
                platform=record.platform,
                status=getattr(record, "status", "unknown"),
                runbook_state=runbook_state,
                runbook_score=runbook_score,
                checked_at=checked_at,
                steps=steps,
                metadata={
                    "requested_by": requested_by,
                    "integration_type": getattr(record, "integration_type", "unknown"),
                },
            ),
        )

    items.sort(
        key=lambda item: (
            0 if item.runbook_state in {"missing", "retired"} else 1 if item.runbook_state in {"partial", "draft"} else 2,
            -item.runbook_score,
            item.platform,
            item.slug,
        ),
    )

    return IntegrationRunbooksView(
        title="Integration Runbooks",
        total=len(items),
        ready_count=ready_count,
        partial_count=partial_count,
        missing_count=missing_count,
        items=items,
        metadata={
            "requested_by": requested_by,
        },
    )
