from fastapi import APIRouter, HTTPException, Query
from app.schemas.scan import ScanHistoryItem, ScanHistoryResponse
from app.services.history import read_scan_history, get_scan_by_id

router = APIRouter()

@router.get("/", response_model=ScanHistoryResponse)
def get_scan_history(limit: int = Query(default=20, ge=1, le=200)):
    items = read_scan_history(limit=limit)
    return {
        "count": len(items),
        "items": items
    }

@router.get("/{scan_id}", response_model=ScanHistoryItem)
def get_scan_record(scan_id: str):
    item = get_scan_by_id(scan_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scan not found")
    return item
