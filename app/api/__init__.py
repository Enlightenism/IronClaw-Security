from app.api.action_execute import router as action_execute_router
from app.api.action_guard import router as action_guard_router
from app.api.auditlog import router as audit_log_router
from app.api.history import router as history_router
from app.api.policy import router as policy_router
from app.api.requestcontext import router as request_context_router
from app.api.review_queue import router as review_queue_router
from app.api.root import router as root_router
from app.api.scan import router as scan_router
from app.api.system import router as system_router
from app.api.telemetry_access import router as telemetry_access_router
from app.api.ui_status import router as ui_status_router

__all__ = [
    "action_execute_router",
    "action_guard_router",
    "audit_log_router",
    "history_router",
    "policy_router",
    "request_context_router",
    "review_queue_router",
    "root_router",
    "scan_router",
    "system_router",
    "telemetry_access_router",
    "ui_status_router",
]