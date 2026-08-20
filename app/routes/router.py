from __future__ import annotations

from fastapi import APIRouter

from app.routes.audit import router as audit_router
from app.routes.auditexplorer import router as auditexplorer_router
from app.routes.auditlog import router as auditlog_router
from app.routes.behavioral_baseline import router as behavioral_baseline_router
from app.routes.customerkeys import router as customerkeys_router
from app.routes.dashboard import router as dashboard_router
from app.routes.deployment import router as deployment_router
from app.routes.incidents import router as incidents_router
from app.routes.install_keys import router as install_keys_router
from app.routes.organizations import router as organizations_router
from app.routes.quarantine import router as quarantine_router
from app.routes.reviewqueue import router as reviewqueue_router
from app.ui.review import router as ui_review_router
from app.ui.reviewqueue import router as ui_reviewqueue_router

router = APIRouter()

_INCLUDED_ROUTERS = (
    audit_router,
    auditexplorer_router,
    auditlog_router,
    behavioral_baseline_router,
    customerkeys_router,
    dashboard_router,
    deployment_router,
    incidents_router,
    install_keys_router,
    organizations_router,
    quarantine_router,
    reviewqueue_router,
    ui_review_router,
    ui_reviewqueue_router,
)

for included_router in _INCLUDED_ROUTERS:
    router.include_router(included_router)
