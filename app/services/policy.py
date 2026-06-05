import os
from typing import Any

from app.services.heuristics import _get_threshold  # type: ignore[attr-defined]
from app.services.rules import ALL_RULE_GROUPS


def is_policy_loaded_from_db() -> bool:
    """Return True when live DB rules are active, False when on cold-start defaults.

    Delegates to the canonical flag in action_policy to preserve a single
    source of truth.  This accessor exists so any module that imports from
    app.services.policy can resolve the symbol without coupling directly to
    action_policy.
    """
    from app.services.action_policy import is_policy_loaded_from_db as _loaded  # noqa: PLC0415

    return _loaded()


def get_policy_status() -> dict[str, Any]:
    severity_counts: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    category_counts: dict[str, int] = {}
    rule_count: int = 0

    for group in ALL_RULE_GROUPS:
        for rule in group:
            sev = rule["severity"]
            cat = rule["category"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            category_counts[cat] = category_counts.get(cat, 0) + 1
            rule_count += 1

    unicode_normalization_enabled = True  # _normalize_text uses NFKC + zero-width stripping

    return {
        "heuristic_threshold": _get_threshold(),
        "heuristic_threshold_env": os.environ.get("IRONCLAW_HEURISTIC_THRESHOLD"),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "unicode_normalization_enabled": unicode_normalization_enabled,
        "rule_count": rule_count,
    }
