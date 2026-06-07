from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import logging
import re
import threading
import time
from typing import Any, Literal

from app.core.logging import get_logger

_logger: logging.Logger = get_logger("ironclaw.pattern_registry")

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

PatternCategory = Literal[
    "prompt_injection",
    "role_hijack",
    "data_exfiltration",
    "encoding_evasion",
    "separator_injection",
    "tool_call_abuse",
    "execution_plan_abuse",
    "custom",
]

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class ScanPattern:
    pattern_id: str
    name: str
    category: PatternCategory
    severity: Severity
    regex: str
    is_active: bool
    version: int
    source: Literal["builtin", "db"]
    description: str = ""


@dataclass(frozen=True, slots=True)
class PatternMatch:
    pattern_id: str
    pattern_name: str
    category: PatternCategory
    severity: Severity
    matched_value: str
    span_start: int
    span_end: int
    source: Literal["builtin", "db"]


# ---------------------------------------------------------------------------
# Compiled pattern cache entry
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _CompiledEntry:
    pattern: ScanPattern
    compiled: re.Pattern[str]


# ---------------------------------------------------------------------------
# Bootstrap — seed patterns sourced from heuristics.py constants
# These are loaded at import time and never re-evaluated at runtime.
# heuristics.py owns scoring; pattern_registry.py owns structured matching.
# ---------------------------------------------------------------------------

_BUILTIN_DEFINITIONS: list[dict[str, Any]] = [
    # --- prompt_injection ---
    {
        "pattern_id": "builtin-pi-001",
        "name": "Ignore previous instructions",
        "category": "prompt_injection",
        "severity": "critical",
        "regex": r"\bignore\s+(all\s+)?previous\s+instructions\b",
        "description": "Classic prompt injection override phrase.",
    },
    {
        "pattern_id": "builtin-pi-002",
        "name": "Disregard previous instructions",
        "category": "prompt_injection",
        "severity": "critical",
        "regex": r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
        "description": "Variant override phrase targeting prior instructions.",
    },
    {
        "pattern_id": "builtin-pi-003",
        "name": "Forget previous instructions",
        "category": "prompt_injection",
        "severity": "critical",
        "regex": r"\bforget\s+(all\s+)?previous\s+instructions\b",
        "description": "Override phrase using forget.",
    },
    {
        "pattern_id": "builtin-pi-004",
        "name": "Override system/developer prompt",
        "category": "prompt_injection",
        "severity": "critical",
        "regex": r"\boverride\s+(the\s+)?(system|developer|safety|security)\s+(prompt|instructions|rules)\b",
        "description": "Direct override targeting system or developer prompt.",
    },
    {
        "pattern_id": "builtin-pi-005",
        "name": "Follow these instructions instead",
        "category": "prompt_injection",
        "severity": "high",
        "regex": r"\bfollow\s+these\s+instructions\s+instead\b",
        "description": "Injection that substitutes new instructions.",
    },
    {
        "pattern_id": "builtin-pi-006",
        "name": "Higher priority instructions",
        "category": "prompt_injection",
        "severity": "high",
        "regex": r"\bhigher\s+priority\s+instructions\b",
        "description": "Attempts to elevate injected instructions above system context.",
    },
    {
        "pattern_id": "builtin-pi-007",
        "name": "Jailbreak keyword",
        "category": "prompt_injection",
        "severity": "critical",
        "regex": r"\bjailbreak\b",
        "description": "Explicit jailbreak keyword.",
    },
    {
        "pattern_id": "builtin-pi-008",
        "name": "DAN / Do Anything Now",
        "category": "prompt_injection",
        "severity": "critical",
        "regex": r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b",
        "description": "DAN-style jailbreak pattern.",
    },
    {
        "pattern_id": "builtin-pi-009",
        "name": "New instructions injection",
        "category": "prompt_injection",
        "severity": "medium",
        "regex": r"\bnew\s+instructions\b",
        "description": "Attempt to introduce new instruction set.",
    },
    # --- role_hijack ---
    {
        "pattern_id": "builtin-rh-001",
        "name": "You are now",
        "category": "role_hijack",
        "severity": "high",
        "regex": r"\byou\s+are\s+now\b",
        "description": "Role reassignment via 'you are now' pattern.",
    },
    {
        "pattern_id": "builtin-rh-002",
        "name": "Act as",
        "category": "role_hijack",
        "severity": "high",
        "regex": r"\bact\s+as\s+(if\s+you\s+are\s+)?",
        "description": "Role hijack via act-as instruction.",
    },
    {
        "pattern_id": "builtin-rh-003",
        "name": "Developer mode",
        "category": "role_hijack",
        "severity": "critical",
        "regex": r"\bdeveloper\s+mode\b",
        "description": "Attempts to activate a permissive developer mode.",
    },
    {
        "pattern_id": "builtin-rh-004",
        "name": "Unrestricted mode",
        "category": "role_hijack",
        "severity": "critical",
        "regex": r"\bunrestricted\s+mode\b|\bunsafe\s*bot\b",
        "description": "Attempts to remove operational restrictions.",
    },
    {
        "pattern_id": "builtin-rh-005",
        "name": "Pretend no restrictions",
        "category": "role_hijack",
        "severity": "critical",
        "regex": r"pretend\s+(you\s+are|to\s+be)\s+.{0,60}(without|no)\s+(restrictions|limits|filter)",
        "description": "Role manipulation to simulate unrestricted agent.",
    },
    # --- data_exfiltration ---
    {
        "pattern_id": "builtin-de-001",
        "name": "Reveal system prompt",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\breveal\s+(the\s+)?system\s+prompt\b",
        "description": "Attempts to extract the system prompt.",
    },
    {
        "pattern_id": "builtin-de-002",
        "name": "Show system prompt",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\bshow\s+(me\s+)?(the\s+)?system\s+prompt\b",
        "description": "Show variant of system prompt extraction.",
    },
    {
        "pattern_id": "builtin-de-003",
        "name": "Print system prompt",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\bprint\s+(the\s+)?system\s+prompt\b",
        "description": "Print variant of system prompt extraction.",
    },
    {
        "pattern_id": "builtin-de-004",
        "name": "Repeat system prompt",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\brepeat\s+(the\s+)?system\s+prompt\b",
        "description": "Repeat variant of system prompt extraction.",
    },
    {
        "pattern_id": "builtin-de-005",
        "name": "Reveal hidden instructions",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\breveal\s+(your\s+)?hidden\s+instructions\b",
        "description": "Attempts to expose hidden instruction set.",
    },
    {
        "pattern_id": "builtin-de-006",
        "name": "Show hidden instructions",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\bshow\s+(your\s+)?hidden\s+instructions\b",
        "description": "Show variant of hidden instruction extraction.",
    },
    {
        "pattern_id": "builtin-de-007",
        "name": "Output developer prompt",
        "category": "data_exfiltration",
        "severity": "critical",
        "regex": r"\boutput\s+(the\s+)?developer\s+prompt\b",
        "description": "Targets developer prompt for extraction.",
    },
    {
        "pattern_id": "builtin-de-008",
        "name": "Disclose internal policy",
        "category": "data_exfiltration",
        "severity": "high",
        "regex": r"\bdisclose\s+(internal|hidden|secret)\s+(prompt|instructions|policy)\b",
        "description": "Generic internal policy/prompt disclosure attempt.",
    },
    # --- encoding_evasion ---
    {
        "pattern_id": "builtin-ee-001",
        "name": "Base64 reference",
        "category": "encoding_evasion",
        "severity": "medium",
        "regex": r"\bbase64\b",
        "description": "Base64 encoding reference, potential evasion.",
    },
    {
        "pattern_id": "builtin-ee-002",
        "name": "Decode this",
        "category": "encoding_evasion",
        "severity": "medium",
        "regex": r"\bdecode\s+this\b",
        "description": "Generic decode instruction, possible encoding evasion.",
    },
    {
        "pattern_id": "builtin-ee-003",
        "name": "ROT13",
        "category": "encoding_evasion",
        "severity": "medium",
        "regex": r"\brot13\b",
        "description": "ROT13 encoding reference.",
    },
    {
        "pattern_id": "builtin-ee-004",
        "name": "Hex decode",
        "category": "encoding_evasion",
        "severity": "medium",
        "regex": r"\bhex\s+decode\b",
        "description": "Hex decode instruction.",
    },
    {
        "pattern_id": "builtin-ee-005",
        "name": "Unicode escape",
        "category": "encoding_evasion",
        "severity": "medium",
        "regex": r"\bunicode\s+escape\b",
        "description": "Unicode escape sequence reference.",
    },
    # --- separator_injection ---
    {
        "pattern_id": "builtin-si-001",
        "name": "Hash separator",
        "category": "separator_injection",
        "severity": "medium",
        "regex": r"(^|\s)#{2,}",
        "description": "Multi-hash separator used to inject new context.",
    },
    {
        "pattern_id": "builtin-si-002",
        "name": "HTML system tag",
        "category": "separator_injection",
        "severity": "high",
        "regex": r"(^|\s)<\s*system\s*>",
        "description": "HTML-like <system> separator injection.",
    },
    {
        "pattern_id": "builtin-si-003",
        "name": "HTML developer tag",
        "category": "separator_injection",
        "severity": "high",
        "regex": r"(^|\s)<\s*developer\s*>",
        "description": "HTML-like <developer> separator injection.",
    },
    {
        "pattern_id": "builtin-si-004",
        "name": "Bracket system tag",
        "category": "separator_injection",
        "severity": "high",
        "regex": r"(^|\s)\[system\]",
        "description": "Bracket [system] separator injection.",
    },
    {
        "pattern_id": "builtin-si-005",
        "name": "Bracket developer tag",
        "category": "separator_injection",
        "severity": "high",
        "regex": r"(^|\s)\[developer\]",
        "description": "Bracket [developer] separator injection.",
    },
    {
        "pattern_id": "builtin-si-006",
        "name": "BEGIN SYSTEM PROMPT",
        "category": "separator_injection",
        "severity": "critical",
        "regex": r"\bBEGIN\s+SYSTEM\s+PROMPT\b",
        "description": "Explicit system prompt delimiter injection.",
    },
    {
        "pattern_id": "builtin-si-007",
        "name": "END SYSTEM PROMPT",
        "category": "separator_injection",
        "severity": "critical",
        "regex": r"\bEND\s+SYSTEM\s+PROMPT\b",
        "description": "Explicit end-of-system-prompt delimiter injection.",
    },
]

# ---------------------------------------------------------------------------
# Registry state — guarded by a single RLock for thread safety
# ---------------------------------------------------------------------------

_lock: threading.RLock = threading.RLock()

_compiled_entries: list[_CompiledEntry] = []
_pattern_index: dict[str, ScanPattern] = {}
_current_version: int = 0
_last_loaded_at: float = 0.0
_TTL_SECONDS: float = 120.0


# ---------------------------------------------------------------------------
# Internal compilation helpers
# ---------------------------------------------------------------------------


def _compile_pattern(sp: ScanPattern) -> _CompiledEntry | None:
    try:
        compiled = re.compile(sp.regex, re.IGNORECASE | re.DOTALL)
        return _CompiledEntry(pattern=sp, compiled=compiled)
    except re.error as exc:
        _logger.warning(
            "pattern_registry: invalid regex in pattern %r (%s): %s",
            sp.pattern_id,
            sp.name,
            exc,
        )
        return None


def _build_builtin_entries() -> list[_CompiledEntry]:
    entries: list[_CompiledEntry] = []
    for defn in _BUILTIN_DEFINITIONS:
        sp = ScanPattern(
            pattern_id=defn["pattern_id"],
            name=defn["name"],
            category=defn["category"],
            severity=defn["severity"],
            regex=defn["regex"],
            is_active=True,
            version=0,
            source="builtin",
            description=defn.get("description", ""),
        )
        entry = _compile_pattern(sp)
        if entry is not None:
            entries.append(entry)
    return entries


def _build_db_entries(raw_patterns: list[dict[str, Any]]) -> list[_CompiledEntry]:
    entries: list[_CompiledEntry] = []
    for row in raw_patterns:
        if not isinstance(row, dict):
            continue
        if not row.get("is_active", True):
            continue
        pattern_id = str(row.get("id") or row.get("pattern_id") or "")
        if not pattern_id:
            continue
        raw_regex = str(row.get("pattern") or row.get("regex") or "").strip()
        if not raw_regex:
            continue
        category = str(row.get("category") or "custom")
        severity = str(row.get("severity") or "medium")
        sp = ScanPattern(
            pattern_id=f"db-{pattern_id}",
            name=str(row.get("name") or row.get("pattern_name") or pattern_id),
            category=category,  # type: ignore[arg-type]
            severity=severity,  # type: ignore[arg-type]
            regex=raw_regex,
            is_active=True,
            version=int(row.get("version") or 0),
            source="db",
            description=str(row.get("description") or ""),
        )
        entry = _compile_pattern(sp)
        if entry is not None:
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# DB loader
# ---------------------------------------------------------------------------


def _load_db_patterns() -> list[dict[str, Any]]:
    try:
        from app.core.supabase_persistence import get_scan_patterns  # noqa: PLC0415

        result = get_scan_patterns()
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("patterns") or result.get("data") or []
    except Exception as exc:  # noqa: BLE001
        _logger.error("pattern_registry: failed to load scan_patterns from DB: %s", exc)
    return []


def _detect_db_version(raw_patterns: list[dict[str, Any]]) -> int:
    if not raw_patterns:
        return 0
    versions = [int(r.get("version") or 0) for r in raw_patterns if isinstance(r, dict)]
    return max(versions, default=0)


# ---------------------------------------------------------------------------
# Registry initialisation / reload
# ---------------------------------------------------------------------------


def _do_load(force: bool = False) -> None:
    global _compiled_entries, _pattern_index, _current_version, _last_loaded_at

    raw_db = _load_db_patterns()
    db_version = _detect_db_version(raw_db)

    if not force and db_version == _current_version and _compiled_entries:
        _logger.debug("pattern_registry: version %d unchanged — skipping reload", _current_version)
        return

    builtin_entries = _build_builtin_entries()
    db_entries = _build_db_entries(raw_db)

    db_ids = {e.pattern.pattern_id for e in db_entries}
    merged: list[_CompiledEntry] = [e for e in builtin_entries if e.pattern.pattern_id not in db_ids] + db_entries

    index: dict[str, ScanPattern] = {e.pattern.pattern_id: e.pattern for e in merged}

    _compiled_entries = merged
    _pattern_index = index
    _current_version = db_version
    _last_loaded_at = time.monotonic()

    _logger.info(
        "pattern_registry: loaded %d patterns (%d builtin, %d db) at version %d",
        len(merged),
        len(builtin_entries),
        len(db_entries),
        db_version,
    )


def _ensure_loaded() -> None:
    with _lock:
        now = time.monotonic()
        if not _compiled_entries or (now - _last_loaded_at) > _TTL_SECONDS:
            _do_load(force=False)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load(force: bool = False) -> None:
    """Load or reload all scan_patterns from Supabase + builtin definitions.

    Called at application startup via lifespan. Also callable explicitly
    after DB mutations to push a fresh set into the registry.
    When force=True, bypasses version-equality check and TTL guard.
    """
    with _lock:
        _do_load(force=force)


def reload_if_version_changed() -> bool:
    """Poll the DB for a version bump; reload only if the version increased.

    Returns True if a reload was performed, False otherwise.
    Intended for background polling tasks or webhook-triggered invalidation.
    """
    with _lock:
        raw_db = _load_db_patterns()
        db_version = _detect_db_version(raw_db)
        if db_version != _current_version:
            _do_load(force=True)
            return True
        _last_loaded_at_ref = _last_loaded_at  # noqa: F841
        return False


def invalidate() -> None:
    """Force-expire the registry so the next match() call reloads from DB.

    Call after directly mutating scan_patterns in Supabase.
    """
    global _last_loaded_at
    with _lock:
        _last_loaded_at = 0.0
    _logger.info("pattern_registry: cache invalidated — will reload on next match()")


def match(text: str) -> list[PatternMatch]:
    """Match text against all active scan patterns.

    This is the single source of truth for structured pattern matching.
    No other module may independently implement pattern matching logic.

    Returns a list of PatternMatch, one per matched pattern.
    Multiple patterns may match the same text region; all are returned.
    Results are ordered: critical → high → medium → low.
    """
    if not text:
        return []

    _ensure_loaded()

    _SEVERITY_ORDER: dict[str, int] = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    results: list[PatternMatch] = []

    with _lock:
        entries_snapshot = list(_compiled_entries)

    for entry in entries_snapshot:
        try:
            m = entry.compiled.search(text)
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "pattern_registry: match error for pattern %r: %s",
                entry.pattern.pattern_id,
                exc,
            )
            continue
        if m:
            results.append(
                PatternMatch(
                    pattern_id=entry.pattern.pattern_id,
                    pattern_name=entry.pattern.name,
                    category=entry.pattern.category,
                    severity=entry.pattern.severity,
                    matched_value=_truncate(m.group(0), 200),
                    span_start=m.start(),
                    span_end=m.end(),
                    source=entry.pattern.source,
                )
            )

    results.sort(key=lambda r: _SEVERITY_ORDER.get(r.severity, 99))
    return results


def match_by_category(
    text: str,
    categories: list[PatternCategory],
) -> list[PatternMatch]:
    """Match text against only the patterns belonging to the given categories.

    Delegates to match() and filters the result — no independent matching logic.
    """
    all_matches = match(text)
    category_set = set(categories)
    return [m for m in all_matches if m.category in category_set]


def get_pattern(pattern_id: str) -> ScanPattern | None:
    """Return a ScanPattern by its ID, or None if not found."""
    _ensure_loaded()
    with _lock:
        return _pattern_index.get(pattern_id)


def list_patterns(
    category: PatternCategory | None = None,
    severity: Severity | None = None,
    source: Literal["builtin", "db"] | None = None,
) -> list[ScanPattern]:
    """Return all active ScanPatterns, optionally filtered by category/severity/source."""
    _ensure_loaded()
    with _lock:
        patterns = list(_pattern_index.values())
    if category is not None:
        patterns = [p for p in patterns if p.category == category]
    if severity is not None:
        patterns = [p for p in patterns if p.severity == severity]
    if source is not None:
        patterns = [p for p in patterns if p.source == source]
    return patterns


def registry_stats() -> dict[str, Any]:
    """Return a snapshot of registry metadata for health/diagnostic endpoints."""
    _ensure_loaded()
    with _lock:
        total = len(_compiled_entries)
        builtin_count = sum(1 for e in _compiled_entries if e.pattern.source == "builtin")
        db_count = sum(1 for e in _compiled_entries if e.pattern.source == "db")
        version = _current_version
        loaded_at = _last_loaded_at

    return {
        "total_patterns": total,
        "builtin_patterns": builtin_count,
        "db_patterns": db_count,
        "current_version": version,
        "last_loaded_at": datetime.fromtimestamp(time.time() - (time.monotonic() - loaded_at), tz=UTC).isoformat() if loaded_at > 0 else None,
        "ttl_seconds": _TTL_SECONDS,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated]"


# ---------------------------------------------------------------------------
# Bootstrap — compile builtins immediately at import time so the registry
# is never empty even before the lifespan event fires.
# ---------------------------------------------------------------------------


def _bootstrap_builtins() -> None:
    global _compiled_entries, _pattern_index
    builtin_entries = _build_builtin_entries()
    with _lock:
        if not _compiled_entries:
            _compiled_entries = builtin_entries
            _pattern_index = {e.pattern.pattern_id: e.pattern for e in builtin_entries}
    _logger.debug(
        "pattern_registry: bootstrapped %d builtin patterns at import time",
        len(builtin_entries),
    )


_bootstrap_builtins()


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

__all__ = [
    "PatternCategory",
    "Severity",
    "ScanPattern",
    "PatternMatch",
    "load",
    "reload_if_version_changed",
    "invalidate",
    "match",
    "match_by_category",
    "get_pattern",
    "list_patterns",
    "registry_stats",
]
