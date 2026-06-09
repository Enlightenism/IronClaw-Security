from __future__ import annotations

# This module is the canonical mount point used by main.py.
# The route implementation lives in app.api.uidataretention.
# Re-export its router so main.py picks up GET /ui/data-retention.
from app.api.uidataretention import router as router  # noqa: PLC0414

__all__ = ["router"]
