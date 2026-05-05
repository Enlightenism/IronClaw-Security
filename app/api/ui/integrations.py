from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.integrations import _record_slug
from app.services.integrationrollout import get_integration_rollout_service
from app.services.integrationstatemachine import get_integration_state_machine
from app.services.integrationtelemetry import get_integration_telemetry_service
from app.services.integrationregistry import get_integration_registry
from app.ui.uiintegrations import get_ui_integrations_page


router = APIRouter(prefix="/ui/integrations", tags=["ui-integrations"])


@router.get("")
def read_ui_integrations() -> dict[str, object]:
    return get_ui_integrations_page()


@router.get("/{integration_id}")
def read_ui_integration_detail(integration_id: str) -> dict[str, object]:
    registry = get_integration_registry()
    record = registry.get_integration(integration_id)

    if record is None:
        normalized_id = integration_id.strip().lower()
        for item in registry.list_integrations():
            if _record_slug(item) == normalized_id:
                record = item
                break

    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")

    slug = _record_slug(record)
    rollout_service = get_integration_rollout_service()
    telemetry_service = get_integration_telemetry_service()
    state_machine = get_integration_state_machine()

    rollout = rollout_service.plan_rollout(record.integrationid)
    telemetry = telemetry_service.list_events(record.integrationid)
    allowed_targets = state_machine.allowed_targets(record.integrationid) or []

    return {
        "pageid": "ui-integration-detail",
        "title": record.displayname,
        "section": "platform",
        "status": "ok",
        "service": "IronClaw-Security",
        "integration": {
            "integration_id": record.integrationid,
            "slug": slug,
            "platform": slug,
            "display_name": record.displayname,
            "status": record.status,
            "description": record.description,
            "version": record.version,
            "adapter_module": record.adaptermodule,
            "settings_route": record.settingsroute,
            "verification_route": record.verificationroute,
            "manifest_route": record.manifestroute,
            "tags": list(record.tags),
            "metadata": dict(record.metadata),
            "capabilities": [
                {
                    "name": capability.name,
                    "enabled": capability.enabled,
                    "maturity": capability.maturity,
                    "notes": capability.notes,
                }
                for capability in record.capabilities
            ],
        },
        "rollout": (
            {
                "stage": rollout.stage,
                "ready": rollout.ready,
                "updated_at": rollout.updatedat,
                "summary": rollout.summary,
                "steps": [
                    {
                        "step_id": step.stepid,
                        "label": step.label,
                        "completed": step.completed,
                        "detail": step.detail,
                    }
                    for step in rollout.steps
                ],
            }
            if rollout is not None
            else None
        ),
        "allowed_state_targets": allowed_targets,
        "telemetry": [
            {
                "event_id": event.eventid,
                "event_type": event.eventtype,
                "level": event.level,
                "message": event.message,
                "created_at": event.createdat,
                "metadata": dict(event.metadata),
            }
            for event in telemetry
        ],
    }