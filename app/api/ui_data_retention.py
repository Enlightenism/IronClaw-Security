from __future__ import annotations

# Route ownership for GET /ui/data-retention lives exclusively in
# app/api/uidataretention.py. This module is retained as a stub so
# main.py can import it without error. It registers no routes.
from fastapi import APIRouter

router = APIRouter(
    prefix="/ui",
    tags=["ui-data-retention"],
)
