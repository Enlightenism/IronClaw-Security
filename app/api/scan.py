from fastapi import APIRouter
from app.schemas.scan import ScanRequest, ScanResult
from app.services.scanner import perform_scan
from app.services.history import append_scan_result

router = APIRouter()

@router.post("/", response_model=ScanResult)
def create_scan(request: ScanRequest):
    result = perform_scan(request.target_type, request.target_value)
    saved = append_scan_result(result)
    return ScanResult(**saved)
