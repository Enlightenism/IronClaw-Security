from datetime import datetime, UTC
from pathlib import Path
import json
import uuid

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
HISTORY_FILE = DATA_DIR / "scan_history.jsonl"

def build_scan_id(record: dict) -> str:
    seed = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return uuid.uuid5(uuid.NAMESPACE_URL, seed).hex

def append_scan_result(result: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        **result
    }
    record["scan_id"] = build_scan_id(record)
    with HISTORY_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record

def read_scan_history(limit: int = 50) -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    with HISTORY_FILE.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    records = [json.loads(line) for line in lines]
    for record in records:
        if "scan_id" not in record:
            record["scan_id"] = build_scan_id(record)
    return records[-limit:][::-1]

def get_scan_by_id(scan_id: str) -> dict | None:
    records = read_scan_history(limit=1000)
    for record in records:
        if record.get("scan_id") == scan_id:
            return record
    return None
