from __future__ import annotations

from core.auth import authenticate_api_key
from orchestrator.orchestrator import Orchestrator
from review.incidentservice import IncidentService


def test_legacy_modules_resolve_to_canonical_packages() -> None:
    assert callable(authenticate_api_key)
    assert hasattr(Orchestrator, "orchestrate")
    assert hasattr(IncidentService, "open_incident")
