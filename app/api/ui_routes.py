from __future__ import annotations

from fastapi import FastAPI

from app.api.ui_admin_operators import router as ui_admin_operators_router
from app.api.ui_admin_roles import router as ui_admin_roles_router
from app.api.ui_audit_log import router as ui_audit_log_router
from app.api.ui_data_retention import router as ui_data_retention_router
from app.api.ui_execution_test_console import router as ui_execution_test_console_router
from app.api.ui_incident_triage import router as ui_incident_triage_router
from app.api.ui_integrations import router as ui_integrations_router
from app.api.ui_request_stream import router as ui_request_stream_router
from app.api.ui_runtime_status import router as ui_runtime_status_router
from app.api.ui_system_diagnostics import router as ui_system_diagnostics_router


def include_ui_routers(app: FastAPI) -> None:
    app.include_router(ui_integrations_router)
    app.include_router(ui_execution_test_console_router)
    app.include_router(ui_runtime_status_router)
    app.include_router(ui_audit_log_router)
    app.include_router(ui_system_diagnostics_router)
    app.include_router(ui_data_retention_router)
    app.include_router(ui_incident_triage_router)
    app.include_router(ui_admin_operators_router)
    app.include_router(ui_admin_roles_router)
    app.include_router(ui_request_stream_router)