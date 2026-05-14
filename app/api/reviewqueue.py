from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies.api_key import require_api_key

router = APIRouter(
    prefix="/api/review-queue",
    tags=["api-inventory"],
    dependencies=[Depends(require_api_key)],
)


@router.get("")
def api_review_queue_inventory() -> dict[str, str]:
    return {
        "section": "review-queue",
        "summary_path": "/guard/reviews/summary",
        "list_path": "/guard/reviews",
        "pending_path": "/guard/reviews/pending",
        "detail_path": "/guard/reviews/{review_id}",
        "approve_path": "/guard/reviews/{review_id}/approve",
        "reject_path": "/guard/reviews/{review_id}/reject",
    }
