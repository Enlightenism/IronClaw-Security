import os
from typing import Dict, Any

from app.services.rules import ALL_RULE_GROUPS
from app.services.heuristics import _get_threshold  # type: ignore[attr-defined]


def get_policy_status() -> Dict[str, Any]:
    severity_counts: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    category_counts: Dict[str, int] = {}

    for group in ALL_RULE_GROUPS:
        for rule in group:
            sev = rule["severity"]
            cat = rule["category"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1

    unicode_normalization_enabled = True  # _normalize_text uses NFKC + zero-width stripping

    return {
        "heuristic_threshold": _get_threshold(),
        "heuristic_threshold_env": os.environ.get("IRONCLAW_HEURISTIC_THRESHOLD"),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "unicode_normalization_enabled": unicode_normalization_enabled,
    }
