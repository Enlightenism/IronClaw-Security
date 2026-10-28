from __future__ import annotations

from pydantic import ValidationError
import pytest

from app.config import RISK_THRESHOLD_BLOCK_MIN
from app.schemas.scan import (
    BatchScanRequest,
    BatchScanResponse,
    ScanHistoryItem,
    ScanHistoryListResponse,
    ScanHistoryResponse,
    ScanRequest,
    ScanResponse,
    ScanResult,
    ScanSummary,
    ScanVerdict,
)

# ---------------------------------------------------------------------------
# Alias integrity
# ---------------------------------------------------------------------------


def test_scan_result_is_alias_of_scan_response():
    assert ScanResult is ScanResponse


def test_scan_history_response_is_alias_of_list_response():
    assert ScanHistoryResponse is ScanHistoryListResponse


# ---------------------------------------------------------------------------
# ScanRequest — target_type validator
# ---------------------------------------------------------------------------

VALID_TARGET_TYPES = [
    "prompt",
    "github_repo",
    "skill",
    "archive",
    "url",
    "text",
    "local_path",
]


@pytest.mark.parametrize("target_type", VALID_TARGET_TYPES)
def test_scan_request_valid_target_types(target_type):
    req = ScanRequest(target_type=target_type, target_value="test input")
    assert req.target_type == target_type


def test_scan_request_invalid_target_type():
    with pytest.raises(ValidationError):
        ScanRequest(target_type="malicious_type", target_value="x")


def test_scan_request_blank_target_value_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(target_type="prompt", target_value="")


def test_scan_request_whitespace_only_target_value_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(target_type="prompt", target_value="   ")


def test_scan_request_target_value_too_long_rejected():
    with pytest.raises(ValidationError):
        ScanRequest(target_type="prompt", target_value="x" * 5001)


def test_scan_request_optional_client_id_defaults_none():
    req = ScanRequest(target_type="prompt", target_value="hello")
    assert req.client_id is None


# ---------------------------------------------------------------------------
# ScanResponse — verdict validator + risk_score bounds + auto_timestamp
# ---------------------------------------------------------------------------

_BASE_RESPONSE = dict(
    verdict="allow",
    summary="clean",
    target_type="prompt",
    target_value="hello",
    risk_score=0,
)


@pytest.mark.parametrize("verdict", ["allow", "block"])
def test_scan_response_valid_verdicts(verdict):
    r = ScanResponse(**{**_BASE_RESPONSE, "verdict": verdict})
    assert r.verdict == verdict


@pytest.mark.parametrize("verdict", ["warn", "quarantine"])
def test_scan_response_rejects_legacy_verdicts(verdict):
    with pytest.raises(ValidationError):
        ScanResponse(**{**_BASE_RESPONSE, "verdict": verdict})


def test_scan_response_invalid_verdict_rejected():
    with pytest.raises(ValidationError):
        ScanResponse(**{**_BASE_RESPONSE, "verdict": "pass"})


def test_scan_response_risk_score_lower_bound():
    r = ScanResponse(**{**_BASE_RESPONSE, "risk_score": 0})
    assert r.risk_score == 0


def test_scan_response_risk_score_upper_bound():
    r = ScanResponse(**{**_BASE_RESPONSE, "risk_score": 100})
    assert r.risk_score == 100


def test_scan_response_risk_score_below_zero_rejected():
    with pytest.raises(ValidationError):
        ScanResponse(**{**_BASE_RESPONSE, "risk_score": -1})


def test_scan_response_risk_score_above_100_rejected():
    with pytest.raises(ValidationError):
        ScanResponse(**{**_BASE_RESPONSE, "risk_score": 101})


def test_scan_response_auto_timestamp_populated():
    r = ScanResponse(**_BASE_RESPONSE)
    assert r.timestamp is not None
    assert "T" in r.timestamp


def test_scan_response_explicit_timestamp_preserved():
    r = ScanResponse(**{**_BASE_RESPONSE, "timestamp": "2026-01-01T00:00:00+00:00"})
    assert r.timestamp == "2026-01-01T00:00:00+00:00"


def test_scan_response_default_list_fields_are_empty():
    r = ScanResponse(**_BASE_RESPONSE)
    assert r.matched_patterns == []
    assert r.risky_files == []
    assert r.checks_loaded == []
    assert r.failed_checks == []


def test_scan_result_alias_instantiates_identically():
    r = ScanResult(**_BASE_RESPONSE)
    assert isinstance(r, ScanResponse)


# ---------------------------------------------------------------------------
# ScanVerdict
# ---------------------------------------------------------------------------


def test_scan_verdict_valid():
    v = ScanVerdict(verdict="block", risk_score=85, summary="dangerous")
    assert v.verdict == "block"
    assert v.risk_score == 85


def test_scan_verdict_invalid_verdict_rejected():
    with pytest.raises(ValidationError):
        ScanVerdict(verdict="skip", risk_score=10, summary="x")


@pytest.mark.parametrize("verdict", ["warn", "quarantine"])
def test_scan_verdict_rejects_legacy_verdicts(verdict):
    with pytest.raises(ValidationError):
        ScanVerdict(verdict=verdict, risk_score=10, summary="x")


def test_scan_verdict_risk_score_out_of_range_rejected():
    with pytest.raises(ValidationError):
        ScanVerdict(verdict="allow", risk_score=200, summary="x")


# ---------------------------------------------------------------------------
# ScanSummary
# ---------------------------------------------------------------------------


def test_scan_summary_minimal():
    s = ScanSummary(verdict="block", risk_score=42, target_type="prompt", summary="ok")
    assert s.verdict == "block"
    assert s.risk_score == 42


@pytest.mark.parametrize("verdict", ["warn", "quarantine"])
def test_scan_summary_rejects_legacy_verdicts(verdict):
    with pytest.raises(ValidationError):
        ScanSummary(verdict=verdict, risk_score=42, target_type="prompt", summary="ok")


# ---------------------------------------------------------------------------
# ScanHistoryItem — guaranteed timestamp
# ---------------------------------------------------------------------------


def test_scan_history_item_auto_timestamp():
    item = ScanHistoryItem(**_BASE_RESPONSE)
    assert item.timestamp is not None
    assert len(item.timestamp) > 0


def test_scan_history_item_explicit_timestamp():
    item = ScanHistoryItem(**{**_BASE_RESPONSE, "timestamp": "2026-06-01T12:00:00+00:00"})
    assert item.timestamp == "2026-06-01T12:00:00+00:00"


@pytest.mark.parametrize("legacy_verdict", ["warn", "quarantine"])
def test_scan_history_item_normalizes_legacy_stored_verdicts(legacy_verdict):
    item = ScanHistoryItem(
        **{
            **_BASE_RESPONSE,
            "verdict": legacy_verdict,
            "risk_score": 5,
            "quarantine_reason": "Stored legacy verdict.",
            "review_status": "pending",
        }
    )
    assert item.verdict == "block"
    assert item.risk_score >= RISK_THRESHOLD_BLOCK_MIN
    assert item.untrusted is True
    assert item.quarantine_reason == "Stored legacy verdict."
    assert item.review_status == "pending"


# ---------------------------------------------------------------------------
# ScanHistoryListResponse
# ---------------------------------------------------------------------------


def test_scan_history_list_response_empty():
    resp = ScanHistoryListResponse(count=0, items=[])
    assert resp.count == 0
    assert resp.items == []


def test_scan_history_list_response_with_items():
    item = ScanHistoryItem(**_BASE_RESPONSE)
    resp = ScanHistoryListResponse(count=1, items=[item])
    assert resp.count == 1
    assert resp.items[0].verdict == "allow"


def test_scan_history_response_alias_works():
    resp = ScanHistoryResponse(count=0, items=[])
    assert isinstance(resp, ScanHistoryListResponse)


# ---------------------------------------------------------------------------
# BatchScanRequest / BatchScanResponse
# ---------------------------------------------------------------------------


def test_batch_scan_request_valid():
    req = BatchScanRequest(items=[ScanRequest(target_type="prompt", target_value="check this")])
    assert len(req.items) == 1


def test_batch_scan_request_empty_items_rejected():
    with pytest.raises(ValidationError):
        BatchScanRequest(items=[])


def test_batch_scan_request_over_limit_rejected():
    items = [ScanRequest(target_type="text", target_value="x")] * 101
    with pytest.raises(ValidationError):
        BatchScanRequest(items=items)


def test_batch_scan_response_shape_schemas():
    r = ScanResponse(**_BASE_RESPONSE)
    resp = BatchScanResponse(count=1, items=[r])
    assert resp.count == 1
    assert resp.items[0].verdict == "allow"
