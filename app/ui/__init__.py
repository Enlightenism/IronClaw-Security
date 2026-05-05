from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, FastAPI

from app.ui.activity.clientprofile import router as client_profile_router
from app.ui.activity.clientsession import router as client_session_activity_router
from app.ui.activity.sessiontimeline import router as session_timeline_router
from app.ui.admin.operators import router as operator_management_router
from app.ui.admin.roles import router as access_control_roles_router
from app.ui.alerts.notifications import router as alert_notifications_router
from app.ui.audit.log import router as audit_log_router
from app.ui.billing_index import router as billing_index_router
from app.ui.billing_manifest import router as billing_manifest_router
from app.ui.billing_registry import router as billing_registry_router
from app.ui.billing_summary import router as billing_summary_router
from app.ui.billing_wallet import router as billing_wallet_router
from app.ui.customer_key_detail import router as customer_key_detail_router
from app.ui.customer_keys import router as customer_keys_router
from app.ui.data.retention import router as data_retention_router
from app.ui.executions.dashboard import router as execution_dashboard_router
from app.ui.executions.detail import router as execution_detail_router
from app.ui.executions.explorer import router as execution_explorer_router
from app.ui.executions.testconsole import router as execution_test_console_router
from app.ui.groq import router as groq_ui_router
from app.ui.health_snapshot import router as health_snapshot_router
from app.ui.incidents.triage import router as incident_triage_router
from app.ui.insights.policy import router as policy_insights_router
from app.ui.integrations.settings import router as integration_settings_router
from app.ui.metrics_summary import router as metrics_summary_router
from app.ui.request_context import router as request_context_router
from app.ui.reviews.detail import router as review_detail_router
from app.ui.reviews.queue import router as review_queue_router
from app.ui.runtime.status import router as runtime_status_router
from app.ui.settings.configuration import router as settings_configuration_router
from app.ui.system.diagnostics import router as system_diagnostics_router
from app.ui.telemetry_access_summary import router as telemetry_access_summary_router
from app.ui.usage_event_detail import router as usage_event_detail_router
from app.ui.usage_reports import router as usage_reports_router


__all__ = [
    "router",
    "UI_ROUTERS",
    "get_ui_routers",
    "iter_ui_routers",
    "include_ui_routers",
    "includeuirouters",
    "ui_router_status",
]


router = APIRouter(prefix="/ui", tags=["ui"])


UI_ROUTERS: tuple[APIRouter, ...] = (
    execution_dashboard_router,
    execution_detail_router,
    review_queue_router,
    review_detail_router,
    policy_insights_router,
    client_session_activity_router,
    client_profile_router,
    session_timeline_router,
    execution_explorer_router,
    settings_configuration_router,
    runtime_status_router,
    audit_log_router,
    execution_test_console_router,
    alert_notifications_router,
    system_diagnostics_router,
    integration_settings_router,
    data_retention_router,
    incident_triage_router,
    operator_management_router,
    access_control_roles_router,
    groq_ui_router,
    billing_manifest_router,
    billing_registry_router,
    billing_index_router,
    billing_summary_router,
    billing_wallet_router,
    usage_reports_router,
    usage_event_detail_router,
    telemetry_access_summary_router,
    metrics_summary_router,
    health_snapshot_router,
    customer_keys_router,
    customer_key_detail_router,
    request_context_router,
)


def get_ui_routers() -> tuple[APIRouter, ...]:
    return UI_ROUTERS


def iter_ui_routers() -> Iterable[APIRouter]:
    return iter(UI_ROUTERS)


def include_ui_routers(app: FastAPI) -> None:
    for ui_router in iter_ui_routers():
        app.include_router(ui_router)


def includeuirouters(app: FastAPI) -> None:
    include_ui_routers(app)


@router.get("/status")
def ui_router_status() -> dict[str, object]:
    return {
        "status": "ok",
        "total_routers": len(UI_ROUTERS),
        "routers": [
            {
                "prefix": ui_router.prefix,
                "tags": list(ui_router.tags or []),
            }
            for ui_router in UI_ROUTERS
        ],
    }