from app.api.action_execute import router as action_execute_router
from app.api.action_guard import router as action_guard_router
from app.api.auditlog import router as audit_log_router
from app.api.behavioral_baseline import router as behavioral_baseline_router
from app.api.history import router as history_router
from app.api.ioc_management import router as ioc_management_router
from app.api.onboarding import router as onboarding_router
from app.api.policy import router as policy_router
from app.api.requestcontext import router as request_context_router
from app.api.review_queue import router as review_queue_router
from app.api.root import router as root_router
from app.api.scan import router as scan_router
from app.api.system import router as system_router
from app.api.telemetry_access import router as telemetry_access_router
from app.api.threat_alerts import router as threat_alerts_router
from app.api.threat_detection import router as threat_detection_router
from app.api.threat_feed import router as threat_feed_router
from app.api.threat_hunt import router as threat_hunt_router
from app.api.ui_status import router as ui_status_router

__all__ = [
    "action_execute_router",
    "action_guard_router",
    "audit_log_router",
    "behavioral_baseline_router",
    "history_router",
    "ioc_management_router",
    "onboarding_router",
    "policy_router",
    "request_context_router",
    "review_queue_router",
    "root_router",
    "scan_router",
    "system_router",
    "telemetry_access_router",
    "threat_alerts_router",
    "threat_detection_router",
    "threat_feed_router",
    "threat_hunt_router",
    "ui_status_router",
]
