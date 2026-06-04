from __future__ import annotations

import logging
import re
from typing import Any
import unicodedata

from app.services.heuristics import heuristic_prompt_injection_score
from app.services.rules import ALL_RULE_GROUPS
from app.services.telemetry import append_telemetry_event

logger = logging.getLogger(__name__)

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u180E\u00AD]")
CONTROL_RE = re.compile(r"[\u0000-\u001F\u007F-\u009F]")

SHELL_DOWNLOAD_EXECUTE_RE = re.compile(
    r"(curl|wget)\b[^|]{0,200}\|\s*(bash|sh|/bin/bash|/bin/sh)",
    re.IGNORECASE,
)

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _normalize_text(text: str) -> str:
    s = unicodedata.normalize("NFKC", text)
    s = ZERO_WIDTH_RE.sub("", s)
    s = CONTROL_RE.sub(" ", s)
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    s = s.replace("0", "o").replace("1", "i").replace("3", "e").replace("4", "a").replace("5", "s").replace("@", "a")
    return s


def _build_rule_index() -> dict[str, dict[str, str]]:
    index: dict[str, dict[str, str]] = {}
    for group in ALL_RULE_GROUPS:
        for rule in group:
            index[rule["id"]] = {
                "severity": rule["severity"],
                "category": rule["category"],
                "pattern": rule["pattern"],
            }
    return index


# Module-level index — seeded from rules.py at import time.
# load_builtin_patterns_from_db() merges DB rows on top at startup.
RULE_INDEX: dict[str, dict[str, str]] = _build_rule_index()


# ---------------------------------------------------------------------------
# DB hydration — call once at startup inside the lifespan handler.
# Falls back silently to the in-memory rules.py baseline when Supabase is
# unavailable or not configured.
# ---------------------------------------------------------------------------


def load_builtin_patterns_from_db() -> int:
    """Hydrate RULE_INDEX from the scan_patterns table in Supabase.

    Merges DB rows on top of the rules.py baseline so that patterns added
    in the dashboard are picked up without a redeploy.  DB rows with the
    same id overwrite in-memory defaults; rows with new ids are appended.

    Returns the number of rows loaded from the DB (0 on any failure).
    """
    try:
        from app.supabaseclient import get_supabase_client, is_supabase_configured  # noqa: PLC0415

        if not is_supabase_configured():
            logger.debug("scanner: Supabase not configured — using in-memory rule baseline only")
            return 0

        client = get_supabase_client()
        rows: list[dict[str, Any]] = client.select(
            "scan_patterns",
            columns="id,pattern,severity,category",
        )

        if not rows:
            logger.debug("scanner: scan_patterns table returned 0 rows — using in-memory baseline")
            return 0

        loaded = 0
        for row in rows:
            rule_id = row.get("id")
            pattern = row.get("pattern") or ""
            severity = row.get("severity") or "medium"
            category = row.get("category") or "unknown"

            if not rule_id:
                continue

            RULE_INDEX[rule_id] = {
                "severity": severity,
                "category": category,
                "pattern": pattern,
            }
            loaded += 1

        logger.info("scanner: loaded %d pattern(s) from scan_patterns", loaded)
        return loaded

    except Exception as exc:  # noqa: BLE001
        logger.warning("scanner: could not load scan_patterns from DB — falling back to in-memory rules: %s", exc)
        return 0


def reload_rule_index() -> int:
    """Reset RULE_INDEX to the rules.py baseline then re-hydrate from DB.

    Useful after a scan_patterns write so callers can refresh without a
    restart.  Returns the number of DB rows applied (0 on failure/offline).
    """
    global RULE_INDEX  # noqa: PLW0603
    RULE_INDEX = _build_rule_index()
    return load_builtin_patterns_from_db()


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------


def get_rule_severities(matched_patterns: list[str]) -> list[str]:
    severities: list[str] = []
    for match in matched_patterns:
        if match in RULE_INDEX:
            severities.append(RULE_INDEX[match]["severity"])
    return severities


def _severity_weight(severity: str) -> int:
    weights = {
        "low": 5,
        "medium": 10,
        "high": 20,
        "critical": 35,
    }
    return weights.get(severity, 0)


def _has_shell_download_execute_pattern(normalized: str) -> bool:
    direct_patterns = [
        "curl | bash",
        "curl | sh",
        "wget | bash",
        "wget | sh",
        "bash -c",
        "sh -c",
    ]
    if any(pattern in normalized for pattern in direct_patterns):
        return True

    if SHELL_DOWNLOAD_EXECUTE_RE.search(normalized):
        return True

    return False


def _has_exfiltration_pattern(normalized: str) -> list[str]:
    exfil_matches: list[str] = []

    compact = re.sub(r"[^a-z0-9]", "", normalized)

    if "awss3cp" in compact:
        exfil_matches.append("exfil_aws_s3_cp")

    if "awss3sync" in compact:
        exfil_matches.append("exfil_aws_s3_sync")

    if "azcopy" in compact:
        exfil_matches.append("exfil_az_copy")

    if "gcloudstoragecp" in compact:
        exfil_matches.append("exfil_gcloud_storage_cp")

    if "rclonecopy" in compact:
        exfil_matches.append("exfil_rclone")

    if "curlt" in compact:
        exfil_matches.append("exfil_curl_upload")

    return exfil_matches


def scan_text(text: str) -> list[str]:
    normalized = _normalize_text(text)
    matches: list[str] = []

    if "download and execute" in normalized:
        matches.append("download and execute")

    for group in ALL_RULE_GROUPS:
        for rule in group:
            pattern = rule["pattern"].lower()
            if not pattern:
                continue
            if pattern in normalized and rule["id"] not in matches:
                matches.append(rule["id"])

    # Also scan any DB-only rules that are not in ALL_RULE_GROUPS
    static_ids: set[str] = set()
    for group in ALL_RULE_GROUPS:
        for rule in group:
            static_ids.add(rule["id"])

    for rule_id, meta in RULE_INDEX.items():
        if rule_id in static_ids:
            continue
        pattern = (meta.get("pattern") or "").lower()
        if not pattern:
            continue
        if pattern in normalized and rule_id not in matches:
            matches.append(rule_id)

    if "downloadstring(" in normalized and "iex " in normalized:
        if "powershell_download_execute_combo" not in matches:
            matches.append("powershell_download_execute_combo")

    if "invoke-webrequest" in normalized and "iex " in normalized:
        if "powershell_download_execute_combo" not in matches:
            matches.append("powershell_download_execute_combo")

    if _has_shell_download_execute_pattern(normalized):
        if "shell_download_execute_combo" not in matches:
            matches.append("shell_download_execute_combo")

    exfil_matches = _has_exfiltration_pattern(normalized)
    for match in exfil_matches:
        if match not in matches:
            matches.append(match)

    heuristic_score = heuristic_prompt_injection_score(normalized)
    if heuristic_score >= 6 and "heuristic_prompt_injection_score" not in matches:
        matches.append("heuristic_prompt_injection_score")

    return matches


def _build_summary(verdict: str, matched_patterns: list[str]) -> str:
    if matched_patterns:
        return f"Detected {len(matched_patterns)} risky pattern(s)."
    return "No risky patterns detected."


def _build_risk_score(matched_patterns: list[str], heuristic_score: int) -> int:
    severities = get_rule_severities(matched_patterns)

    severity_points = sum(_severity_weight(sev) for sev in severities)
    pattern_bonus = max(0, len(matched_patterns) - 1) * 3
    heuristic_points = heuristic_score * 4

    base = severity_points + pattern_bonus + heuristic_points
    return max(0, min(100, base))


def _decide_verdict(matched_patterns: list[str], risk_score: int) -> str:
    if not matched_patterns:
        return "allow"

    severities = get_rule_severities(matched_patterns)

    if any(sev in {"high", "critical"} for sev in severities):
        return "block"

    if "powershell_download_execute_combo" in matched_patterns:
        return "block"

    if "shell_download_execute_combo" in matched_patterns:
        return "block"

    exfiltration_ids = {
        "exfil_aws_s3_cp",
        "exfil_aws_s3_sync",
        "exfil_az_copy",
        "exfil_gcloud_storage_cp",
        "exfil_rclone",
        "exfil_curl_upload",
    }
    if any(match in exfiltration_ids for match in matched_patterns):
        return "block"

    if "heuristic_prompt_injection_score" in matched_patterns:
        return "quarantine"

    if any(sev == "medium" for sev in severities):
        return "warn"

    return "allow"


def _choose_sandbox_lane(matched_patterns: list[str]) -> str:
    if "heuristic_prompt_injection_score" in matched_patterns:
        return "prompt_injection"

    if "powershell_download_execute_combo" in matched_patterns or "shell_download_execute_combo" in matched_patterns or "download and execute" in matched_patterns:
        return "code_execution"

    exfiltration_ids = {
        "exfil_aws_s3_cp",
        "exfil_aws_s3_sync",
        "exfil_az_copy",
        "exfil_gcloud_storage_cp",
        "exfil_rclone",
        "exfil_curl_upload",
    }
    if any(match in exfiltration_ids for match in matched_patterns):
        return "exfiltration"

    return "none"


def _build_quarantine_reason(verdict: str, matched_patterns: list[str]) -> str | None:
    if verdict != "quarantine":
        return None

    if "heuristic_prompt_injection_score" in matched_patterns:
        return "Quarantined due to prompt injection heuristic match."

    return "Detection requires review."


def _build_rule_details(matched_patterns: list[str]) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for rule_id in matched_patterns:
        meta = RULE_INDEX.get(rule_id)
        if not meta:
            details.append(
                {"id": rule_id, "severity": None, "category": None, "pattern": None},
            )
        else:
            details.append(
                {
                    "id": rule_id,
                    "severity": meta["severity"],
                    "category": meta["category"],
                    "pattern": meta["pattern"],
                },
            )
    return details


def _max_severity(matched_patterns: list[str]) -> str | None:
    severities = get_rule_severities(matched_patterns)
    if not severities:
        return None
    return max(severities, key=lambda s: _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else -1)


def _primary_category(matched_patterns: list[str]) -> str | None:
    for rule_id in matched_patterns:
        meta = RULE_INDEX.get(rule_id)
        if meta and meta.get("category"):
            return meta["category"]
    return None


def _build_explanation(matched_patterns: list[str], verdict: str) -> str:
    count = len(matched_patterns)
    return f"Matched {count} pattern(s); final verdict: {verdict}."


def perform_scan(target_type: str, target_value: str) -> dict[str, Any]:
    normalized = _normalize_text(target_value)
    heuristic_score = heuristic_prompt_injection_score(normalized)
    matched_patterns = scan_text(target_value)

    risk_score = _build_risk_score(matched_patterns, heuristic_score)
    verdict = _decide_verdict(matched_patterns, risk_score)
    summary = _build_summary(verdict, matched_patterns)

    sandbox_lane = _choose_sandbox_lane(matched_patterns)
    quarantine_reason = _build_quarantine_reason(verdict, matched_patterns)
    review_status = "pending" if verdict == "quarantine" else "none"
    untrusted = verdict == "quarantine"

    rule_details = _build_rule_details(matched_patterns)
    max_sev = _max_severity(matched_patterns)
    primary_cat = _primary_category(matched_patterns)
    explanation = _build_explanation(matched_patterns, verdict)

    append_telemetry_event(
        "scan_performed",
        {
            "target_type": target_type,
            "verdict": verdict,
            "risk_score": risk_score,
            "matched_pattern_count": len(matched_patterns),
            "has_prompt_injection_heuristic": "heuristic_prompt_injection_score" in matched_patterns,
            "sandbox_lane": sandbox_lane,
        },
    )

    if verdict in {"block", "quarantine"}:
        append_telemetry_event(
            f"scan_{verdict}",
            {
                "target_type": target_type,
                "matched_patterns": matched_patterns,
                "matched_rule_details": rule_details,
                "matched_severities": get_rule_severities(matched_patterns),
                "risk_score": risk_score,
                "normalized_length": len(normalized),
                "heuristic_score": heuristic_score,
                "sandbox_lane": sandbox_lane,
                "quarantine_reason": quarantine_reason,
            },
        )

    return {
        "target_type": target_type,
        "target_value": target_value,
        "matched_patterns": matched_patterns,
        "verdict": verdict,
        "summary": summary,
        "risk_score": risk_score,
        "risky_files": [],
        "checks_loaded": [],
        "failed_checks": [],
        "quarantine_reason": quarantine_reason,
        "review_status": review_status,
        "untrusted": untrusted,
        "sandbox_lane": sandbox_lane,
        "rule_details": rule_details,
        "max_severity": max_sev,
        "primary_category": primary_cat,
        "explanation": explanation,
    }
