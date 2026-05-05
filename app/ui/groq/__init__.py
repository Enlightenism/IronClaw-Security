from __future__ import annotations

from fastapi import APIRouter

from app.ui.groq.copilot import router as copilot_router
from app.ui.groq.incidents import router as incidents_router
from app.ui.groq.posture_summary import router as posture_summary_router
from app.ui.groq.prompt_guard_activity_feed import (
    router as prompt_guard_activity_feed_router,
)
from app.ui.groq.prompt_guard_alerts_overview import (
    router as prompt_guard_alerts_overview_router,
)
from app.ui.groq.prompt_guard_alerts_timeline_summary import (
    router as prompt_guard_alerts_timeline_summary_router,
)
from app.ui.groq.prompt_guard_coverage_summary import (
    router as prompt_guard_coverage_summary_router,
)
from app.ui.groq.prompt_guard_dashboard_index import (
    router as prompt_guard_dashboard_index_router,
)
from app.ui.groq.prompt_guard_executive_summary import (
    router as prompt_guard_executive_summary_router,
)
from app.ui.groq.prompt_guard_health_snapshot import (
    router as prompt_guard_health_snapshot_router,
)
from app.ui.groq.prompt_guard_incident_summary import (
    router as prompt_guard_incident_summary_router,
)
from app.ui.groq.prompt_guard_kpi_summary import (
    router as prompt_guard_kpi_summary_router,
)
from app.ui.groq.prompt_guard_metrics import router as prompt_guard_metrics_router
from app.ui.groq.prompt_guard_ops_dashboard import (
    router as prompt_guard_ops_dashboard_router,
)
from app.ui.groq.prompt_guard_performance_snapshot import (
    router as prompt_guard_performance_snapshot_router,
)
from app.ui.groq.prompt_guard_policy import router as prompt_guard_policy_router
from app.ui.groq.prompt_guard_recommendations import (
    router as prompt_guard_recommendations_router,
)
from app.ui.groq.prompt_guard_review_queue_summary import (
    router as prompt_guard_review_queue_summary_router,
)
from app.ui.groq.prompt_guard_risk_posture_summary import (
    router as prompt_guard_risk_posture_summary_router,
)
from app.ui.groq.prompt_guard_signals_summary import (
    router as prompt_guard_signals_summary_router,
)
from app.ui.groq.prompt_guard_status_board_summary import (
    router as prompt_guard_status_board_summary_router,
)
from app.ui.groq.prompt_guard_timeline_summary import (
    router as prompt_guard_timeline_summary_router,
)
from app.ui.groq.prompt_guard_trends import router as prompt_guard_trends_router
from app.ui.groq.prompt_guard_trends_summary import (
    router as prompt_guard_trends_summary_router,
)

router = APIRouter()

router.include_router(incidents_router)
router.include_router(copilot_router)
router.include_router(posture_summary_router)
router.include_router(prompt_guard_policy_router)
router.include_router(prompt_guard_metrics_router)
router.include_router(prompt_guard_recommendations_router)
router.include_router(prompt_guard_trends_router)
router.include_router(prompt_guard_incident_summary_router)
router.include_router(prompt_guard_ops_dashboard_router)
router.include_router(prompt_guard_activity_feed_router)
router.include_router(prompt_guard_alerts_overview_router)
router.include_router(prompt_guard_health_snapshot_router)
router.include_router(prompt_guard_performance_snapshot_router)
router.include_router(prompt_guard_risk_posture_summary_router)
router.include_router(prompt_guard_review_queue_summary_router)
router.include_router(prompt_guard_signals_summary_router)
router.include_router(prompt_guard_status_board_summary_router)
router.include_router(prompt_guard_executive_summary_router)
router.include_router(prompt_guard_kpi_summary_router)
router.include_router(prompt_guard_timeline_summary_router)
router.include_router(prompt_guard_coverage_summary_router)
router.include_router(prompt_guard_trends_summary_router)
router.include_router(prompt_guard_alerts_timeline_summary_router)
router.include_router(prompt_guard_dashboard_index_router)

__all__ = ["router"]