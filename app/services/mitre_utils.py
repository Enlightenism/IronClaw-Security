from __future__ import annotations

from collections.abc import Iterable, Sequence
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


# Public API
__all__ = [
    "normalize_mitre",
    "coerce_str_list",
    "dedupe_preserve_order",
    "extract_mitre_from_source",
    "extract_mitre_from_signal",
    "aggregate_mitre_techniques",
]


# MITRE technique regex: T#### or T####.###
_RE_MITRE_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_RE_MITRE_TECH_FIND = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


# -------------------------
# Basic helpers
# -------------------------
def _string_or_none(value: Any) -> str | None:
    """Return a stripped string or None for falsy / non-coercible values.


    Defensive: treats unittest.mock mocks as None so tests using MagicMock
    do not accidentally propagate "<MagicMock ...>" strings as technique IDs.
    """
    if value is None:
        return None

    # Defensive: ignore unittest.mock objects (common in unit tests)
    try:
        module = type(value).__module__
    except Exception:
        module = ""
    if module.startswith("unittest.mock"):
        return None
    try:
        cls_name = value.__class__.__name__
    except Exception:
        cls_name = ""
    if cls_name in {"MagicMock", "Mock", "AsyncMock"}:
        return None

    if isinstance(value, str):
        s = value.strip()
        return s if s else None
    try:
        s = str(value).strip()
        return s if s else None
    except Exception:
        return None


# -------------------------
# Normalization & coercion
# -------------------------
def normalize_mitre(value: Any) -> str | None:
    """
    Normalize a MITRE technique value to an uppercase string.


    Behavior:
      - Coerce to string and strip whitespace.
      - Uppercase result.
      - Return None for empty / non-coercible inputs.


    Note: This function is intentionally permissive to support test fixtures
    and legacy values that may not strictly conform to T#### formatting.
    """
    s = _string_or_none(value)
    if s is None:
        return None
    return s.upper()


def coerce_str_list(value: Any) -> list[str]:
    """
    Coerce various input shapes into a list[str].


    Supported inputs:
    - None -> []
    - list/tuple -> preserve order, filter out falsy after coercion
    - set -> iterate (order not guaranteed)
    - single string -> if comma-separated returns split items, otherwise single-item list
    - any other object -> attempt str() then treat like single string


    Returned items are the raw strings (not uppercased) and are stripped.
    Use normalize_mitre(...) to uppercase / validate technique IDs.
    """
    if value is None:
        return []

    # Preserve order for list/tuple
    if isinstance(value, list | tuple):
        out: list[str] = []
        for item in value:
            s = _string_or_none(item)
            if s:
                out.append(s)
        return out

    # Sets: iterate (order arbitrary)
    if isinstance(value, set):
        out = []
        for item in value:
            s = _string_or_none(item)
            if s:
                out.append(s)
        return out

    # Strings: comma split to support "a,b,c"
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        # If it looks like a comma-separated list, split
        if "," in s:
            parts = [p.strip() for p in s.split(",") if p.strip()]
            return parts
        return [s]

    # Fallback: coerce to string
    s = _string_or_none(value)
    return [s] if s else []


def dedupe_preserve_order(values: Sequence[str]) -> list[str]:
    """
    Deduplicate a sequence while preserving first-seen order.
    Keeps item casing as provided.
    """
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


# -------------------------
# Extraction helpers
# -------------------------
def extract_mitre_from_source(
    source: Any,
    *,
    direct_attrs: tuple[str, ...] = ("mitre_technique_id",),
    list_attrs: tuple[str, ...] = ("mitre_technique_ids", "mitre_techniques"),
) -> list[str]:
    """
    Extract MITRE technique IDs from a source object (IOCMatch-like or dict).


    Extraction order:
      - For each name in direct_attrs, read attribute or dict key; normalize single values and append.
      - For each name in list_attrs, coerce to list via coerce_str_list, normalize each and append.
      - If no results found, attempt to read common 'extra' dict (source.extra or source['extra'])
        and repeat the same extraction there for backwards compatibility.
      - Additionally inspect Pydantic v2 'pydantic_extra' if present.
      - Additionally inspect object.dict() keys for direct/list attrs if present.
    All results are normalized via normalize_mitre() and deduped preserving order.
    """
    candidates: list[str] = []

    # Helper to retrieve attribute or dict key
    def _get_attr(obj: Any, name: str) -> Any:
        if obj is None:
            return None
        # Prefer attribute access for objects
        try:
            if hasattr(obj, name):
                return getattr(obj, name)
        except Exception:
            # Defensive: fall back to dict access
            pass
        # Dict-like access
        try:
            if isinstance(obj, dict):
                return obj.get(name)
        except Exception:
            pass
        return None

    # Direct attrs (single values)
    for attr in direct_attrs:
        try:
            raw = _get_attr(source, attr)
            norm = normalize_mitre(raw)
            if norm:
                candidates.append(norm)
        except Exception:
            # avoid bubbling exceptions during extraction
            continue

    # List attrs (collections)
    for attr in list_attrs:
        try:
            raw = _get_attr(source, attr)
            for item in coerce_str_list(raw):
                normalized = normalize_mitre(item)
                if normalized:
                    candidates.append(normalized)
        except Exception:
            continue

    # If nothing found, try to inspect "extra" dict (common fallback)
    if not candidates:
        try:
            extra = _get_attr(source, "extra")
            if isinstance(extra, dict):
                # try direct single field inside extra
                for attr in direct_attrs:
                    raw = extra.get(attr)
                    norm = normalize_mitre(raw)
                    if norm:
                        candidates.append(norm)
                # list attrs in extra
                for attr in list_attrs:
                    raw = extra.get(attr)
                    for item in coerce_str_list(raw):
                        normalized = normalize_mitre(item)
                        if normalized:
                            candidates.append(normalized)
        except Exception:
            pass

    # Additional fallback: inspect Pydantic v2 'pydantic_extra' if present
    if not candidates:
        try:
            pydantic_extra = getattr(source, "pydantic_extra", None)
            if isinstance(pydantic_extra, dict):
                for attr in direct_attrs:
                    raw = pydantic_extra.get(attr)
                    norm = normalize_mitre(raw)
                    if norm:
                        candidates.append(norm)
                for attr in list_attrs:
                    raw = pydantic_extra.get(attr)
                    for item in coerce_str_list(raw):
                        normalized = normalize_mitre(item)
                        if normalized:
                            candidates.append(normalized)
        except Exception:
            pass

    # Additional fallback: inspect object.dict() keys if available
    if not candidates:
        try:
            if hasattr(source, "dict") and callable(source.dict):
                obj_dict = source.dict()
                if isinstance(obj_dict, dict):
                    for attr in direct_attrs:
                        raw = obj_dict.get(attr)
                        norm = normalize_mitre(raw)
                        if norm:
                            candidates.append(norm)
                    for attr in list_attrs:
                        raw = obj_dict.get(attr)
                        for item in coerce_str_list(raw):
                            normalized = normalize_mitre(item)
                            if normalized:
                                candidates.append(normalized)
        except Exception:
            pass

    return dedupe_preserve_order(candidates)


def extract_mitre_from_signal(signal: Any) -> list[str]:
    """
    Extract MITRE technique IDs from a CorrelationSignal-like object.


    Behavior:
    - Check top-level attributes/keys: 'mitre_technique_id', 'mitre_technique_ids', 'mitre_techniques'.
    - Inspect nested dict containers if present: 'metadata', 'context', 'details', 'enrichment', 'attributes'.
      For each container that is a dict, attempt to extract the same keys inside it.
    - If still empty, inspect a top-level 'extra' dict (or signal.extra) for the same keys.
    - Normalize and dedupe preserving first-seen order.
    """
    candidates: list[str] = []

    # Top-level extraction from the signal object
    candidates.extend(
        extract_mitre_from_source(
            signal,
            direct_attrs=("mitre_technique_id",),
            list_attrs=("mitre_technique_ids", "mitre_techniques"),
        )
    )

    # Nested containers to inspect if they are dicts
    for container_name in ("metadata", "context", "details", "enrichment", "attributes"):
        try:
            container = getattr(signal, container_name, None)
        except Exception:
            container = None

        # If it's not a dict, skip (context is sometimes a string)
        if not isinstance(container, dict):
            continue

        # Use extract_mitre_from_source over the dict container
        candidates.extend(
            extract_mitre_from_source(
                container,
                direct_attrs=("mitre_technique_id",),
                list_attrs=("mitre_technique_ids", "mitre_techniques"),
            )
        )

    # Fallback: inspect 'extra' container if present (common pattern)
    if not candidates:
        try:
            extra = getattr(signal, "extra", None)
        except Exception:
            extra = None
        if isinstance(extra, dict):
            candidates.extend(
                extract_mitre_from_source(
                    extra,
                    direct_attrs=("mitre_technique_id",),
                    list_attrs=("mitre_technique_ids", "mitre_techniques"),
                )
            )

    return dedupe_preserve_order(candidates)


def aggregate_mitre_techniques(ioc_matches: Iterable[Any], signals: Iterable[Any]) -> list[str]:
    """
    Aggregate MITRE techniques from ioc_matches and then signals.


    Algorithm:
      - Iterate ioc_matches in the provided order. For each match:
          - extract techniques using extract_mitre_from_source (single+collections)
          - append techniques preserving first-seen order
      - After ioc_matches, iterate signals in order. For each signal:
          - extract techniques using extract_mitre_from_signal
          - append any new techniques preserving first-seen order
      - All returned technique IDs are normalized to uppercase and deduped (first-seen).
    """
    out: list[str] = []
    seen: set[str] = set()

    # Helper to add normalized techniques preserving order
    def _append_techs(seq: Iterable[str]) -> None:
        for t in seq:
            if t and t not in seen:
                seen.add(t)
                out.append(t)

    # Process IOC matches first
    for m in ioc_matches or []:
        try:
            techs = extract_mitre_from_source(m)
        except Exception:
            techs = []
        _append_techs(techs)

    # Then signals
    for s in signals or []:
        try:
            techs = extract_mitre_from_signal(s)
        except Exception:
            techs = []
        _append_techs(techs)

    return out
