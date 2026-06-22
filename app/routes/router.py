from __future__ import annotations

from fastapi import APIRouter

from app.routes.actionhistorytest import router as actionhistorytest_router
from app.routes.alerts import router as alerts_router
from app.routes.audit import router as audit_router
from app.routes.auditexplorer import router as auditexplorer_router
from app.routes.auditlog import router as auditlog_router
from app.routes.behavioral_baseline import router as behavioral_baseline_router
from app.routes.billing import router as billing_router
from app.routes.customerkeys import router as customerkeys_router
from app.routes.dashboard import router as dashboard_router
from app.routes.deployment import router as deployment_router
from app.routes.executiondashboard import router as executiondashboard_router
from app.routes.guard import router as guard_router
from app.routes.incidents import router as incidents_router
from app.routes.onboarding import router as onboarding_router
from app.routes.organizations import router as organizations_router
from app.routes.orgs import router as orgs_router
from app.routes.policy import router as policy_router
from app.routes.quarantine import router as quarantine_router
from app.routes.reviewqueue import router as reviewqueue_router
from app.routes.scan import router as scan_router
from app.routes.unitledger import router as unitledger_router
from app.routes.unitwallet import router as unitwallet_router
from app.routes.usage import router as usage_router
from app.ui.review import router as ui_review_router
from app.ui.reviewqueue import router as ui_reviewqueue_router

router = APIRouter()


_INCLUDED_ROUTERS = (
    actionhistorytest_router,
    alerts_router,
    audit_router,
    auditexplorer_router,
    auditlog_router,
    behavioral_baseline_router,
    billing_router,
    customerkeys_router,
    dashboard_router,
    deployment_router,
    executiondashboard_router,
    guard_router,
    incidents_router,
    onboarding_router,
    organizations_router,
    orgs_router,
    policy_router,
    quarantine_router,
    reviewqueue_router,
    scan_router,
    unitledger_router,
    unitwallet_router,
    usage_router,
    ui_review_router,
    ui_reviewqueue_router,
)


for included_router in _INCLUDED_ROUTERS:
    router.include_router(included_router)
