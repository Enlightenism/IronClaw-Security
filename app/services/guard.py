import logging
from typing import Literal, TypedDict

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.services.scanner import perform_scan

logger = logging.getLogger(__name__)

ContextType = Literal["user_prompt", "retrieved_doc", "tool_output", "model_output"]
VerdictType = Literal["allow", "block"]


class GuardDecision(TypedDict):
    context_type: ContextType
    verdict: VerdictType
    scan_id: str | None
    summary: str
    risk_score: int
    matched_patterns: list[str]


def _block_decision(
    context_type: ContextType,
    summary: str,
    *,
    scan_id: str | None = None,
    risk_score: int = 0,
    matched_patterns: list[str] | None = None,
) -> GuardDecision:
    return {
        "context_type": context_type,
        "verdict": "block",
        "scan_id": scan_id,
        "summary": summary,
        "risk_score": max(risk_score, RISK_THRESHOLD_BLOCK_MIN),
        "matched_patterns": matched_patterns or [],
    }


def guard_text(context_type: ContextType, text: str) -> GuardDecision:
    try:
        result = perform_scan("text", text)
    except Exception:  # noqa: BLE001
        logger.exception("guard: scan failed; blocking request")
        return _block_decision(
            context_type,
            "Scan failed (scan_unavailable); request blocked.",
        )

    if not isinstance(result, dict):
        logger.error("guard: scanner returned an invalid result; blocking request")
        return _block_decision(
            context_type,
            "Scan result invalid; request blocked.",
        )

    invalid_result = False

    raw_patterns = result.get("matched_patterns")
    if isinstance(raw_patterns, list):
        if any(not isinstance(pattern, str) for pattern in raw_patterns):
            logger.error("guard: scanner returned invalid matched patterns; blocking request")
            invalid_result = True
        matched_patterns = [str(pattern) for pattern in raw_patterns]
    else:
        logger.error("guard: scanner returned no matched-pattern list; blocking request")
        matched_patterns = []
        invalid_result = True

    raw_failed_checks = result.get("failed_checks")
    if isinstance(raw_failed_checks, list):
        if any(not isinstance(check, str) for check in raw_failed_checks):
            logger.error("guard: scanner returned invalid failed checks; blocking request")
            invalid_result = True
        failed_checks = [str(check) for check in raw_failed_checks]
    else:
        logger.error("guard: scanner returned no failed-check list; blocking request")
        failed_checks = ["invalid_scan_result"]
        invalid_result = True

    raw_risk_score = result.get("risk_score")
    if isinstance(raw_risk_score, int) and not isinstance(raw_risk_score, bool) and 0 <= raw_risk_score <= 100:
        risk_score = raw_risk_score
    else:
        logger.error("guard: scanner returned an invalid risk score; blocking request")
        risk_score = 0
        invalid_result = True

    scan_verdict = result.get("verdict")
    if scan_verdict not in ("allow", "block"):
        logger.error("guard: scanner returned an invalid verdict; blocking request")
        invalid_result = True

    raw_summary = result.get("summary")
    if isinstance(raw_summary, str) and raw_summary.strip():
        summary = raw_summary
    else:
        logger.error("guard: scanner returned no summary; blocking request")
        summary = "Scan result invalid; request blocked."
        invalid_result = True

    raw_scan_id = result.get("scan_id")
    if raw_scan_id is None or isinstance(raw_scan_id, str):
        scan_id = raw_scan_id
    else:
        logger.error("guard: scanner returned an invalid scan id; blocking request")
        scan_id = None
        invalid_result = True

    should_block = invalid_result or scan_verdict != "allow" or bool(matched_patterns) or bool(failed_checks) or risk_score > RISK_THRESHOLD_ALLOW_MAX
    if not should_block:
        return {
            "context_type": context_type,
            "verdict": "allow",
            "scan_id": scan_id,
            "summary": summary,
            "risk_score": risk_score,
            "matched_patterns": matched_patterns,
        }

    if invalid_result:
        summary = "Scan result invalid; request blocked."
    elif failed_checks:
        reason = result.get("quarantine_reason")
        if isinstance(reason, str) and reason:
            summary = f"Scan failed ({reason}); request blocked."
        else:
            summary = f"Scan failed ({', '.join(failed_checks)}); request blocked."
    elif risk_score > RISK_THRESHOLD_ALLOW_MAX and not matched_patterns:
        summary = "Risk score exceeds the configured allow threshold; request blocked."
    elif scan_verdict == "block" and not matched_patterns:
        summary = "Scan blocked the request."

    return _block_decision(
        context_type,
        summary,
        scan_id=scan_id,
        risk_score=risk_score,
        matched_patterns=matched_patterns,
    )
