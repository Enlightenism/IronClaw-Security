# app/models/uipages.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(slots=True)
class PageSection:
    """Single section on a UI summary page."""

    sectionid: str
    title: str
    kind: str
    description: str
    items: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class UIPageDefinition:
    """
    Lightweight UI page contract for internal admin/telemetry views.

    This is intentionally simple for Gen1; you can hang richer UI metadata
    off the metadata dict later without breaking existing contracts.
    """

    pageid: str
    title: str
    path: str
    summary: str
    sections: List[PageSection] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)