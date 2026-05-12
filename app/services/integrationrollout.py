from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.services.integrationregistry import get_integration_registry

RolloutStage = str


@dataclass(slots=True)
class IntegrationRolloutStep:
    stepid: str
    label: str
    completed: bool
    detail: str


@dataclass(slots=True)
class IntegrationRolloutResult:
    integrationid: str
    platform: str
    stage: RolloutStage
    ready: bool
    updatedat: str
    steps: list[IntegrationRolloutStep] = field(default_factory=list)
    summary: str = ""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class IntegrationRolloutService:
    def plan_rollout(self, integrationid: str) -> IntegrationRolloutResult | None:
        registry = get_integration_registry()
        record = registry.get_integration(integrationid)
        if record is None:
            return None

        steps = [
            IntegrationRolloutStep(
                stepid="registered",
                label="Integration registered",
                completed=True,
                detail=record.integrationid,
            ),
            IntegrationRolloutStep(
                stepid="settings-route",
                label="Settings route available",
                completed=record.settingsroute.startswith("/"),
                detail=record.settingsroute,
            ),
            IntegrationRolloutStep(
                stepid="verify-route",
                label="Verification route available",
                completed=record.verificationroute.startswith("/"),
                detail=record.verificationroute,
            ),
            IntegrationRolloutStep(
                stepid="manifest-route",
                label="Manifest route available",
                completed=record.manifestroute.startswith("/"),
                detail=record.manifestroute,
            ),
            IntegrationRolloutStep(
                stepid="status-ready",
                label="Rollout candidate status acceptable",
                completed=record.status in {"configured", "ready", "available"},
                detail=record.status,
            ),
        ]

        ready = all(step.completed for step in steps)
        stage = "ready-for-rollout" if ready else "rollout-blocked"

        return IntegrationRolloutResult(
            integrationid=record.integrationid,
            platform=record.platform,
            stage=stage,
            ready=ready,
            updatedat=_utc_now(),
            steps=steps,
            summary=(
                f"Integration {record.integrationid} rollout stage is {stage}."
            ),
        )


_rollout_service = IntegrationRolloutService()


def get_integration_rollout_service() -> IntegrationRolloutService:
    return _rollout_service