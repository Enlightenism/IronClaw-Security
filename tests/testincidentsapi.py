from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.incidents import (
    get_attack_correlation_service,
    router,
)


class StubAttackCorrelationService:
    def __init__(self) -> None:
        self.calls = []

    def correlate(
        self,
        signals,
        *,
        session_id=None,
        actor_id=None,
        organization_id=None,
        request_id=None,
        metadata=None,
    ):
        self.calls.append(
            {
                "signals": signals,
                "session_id": session_id,
                "actor_id": actor_id,
                "organization_id": organization_id,
                "request_id": request_id,
                "metadata": metadata,
            },
        )
        return {
            "risk_score": 72,
            "risk_band": "high",
            "confidence": 0.88,
            "incident": {
                "incident_id": "inc-001",
                "status": "action_required",
                "severity": "high",
                "signal_count": len(signals),
                "indicators": {
                    "prompt_fingerprints": ["pf-001"],
                    "tools": ["shell"],
                    "files": [],
                    "hashes": [],
                    "domains": [],
                    "ips": [],
                    "campaigns": [],
                    "clusters": [],
                    "ttp_ids": [],
                },
                "linked_reviews": ["rev-001"],
                "linked_quarantine_records": [],
                "escalation_actions": [
                    {
                        "action_id": "act-001",
                        "action": "disable-session",
                        "status": "open",
                    },
                ],
                "malware_summary": None,
                "detonation_summary": None,
                "hostile_context": None,
            },
            "signals": signals,
            "linked_reviews": ["rev-001"],
            "linked_quarantine_records": [],
            "recommended_playbooks": ["prompt-injection-containment"],
            "escalation_actions": [
                {
                    "action_id": "act-001",
                    "action": "disable-session",
                    "status": "open",
                },
            ],
        }


def _build_client(service: StubAttackCorrelationService) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_attack_correlation_service] = lambda: service
    return TestClient(app)


def test_correlate_incidents_returns_correlation_response():
    service = StubAttackCorrelationService()
    client = _build_client(service)

    response = client.post(
        "/incidents/correlate",
        json={
            "signals": [
                {
                    "signal_id": "sig-001",
                    "signal_type": "prompt_injection",
                    "source": "prompt_guard",
                    "severity": "high",
                    "summary": "Prompt attempted tool hijack",
                    "score": 72,
                    "evidence": {
                        "prompt_fingerprints": ["pf-001"],
                        "tools": ["shell"],
                    },
                    "metadata": {"origin": "unit-test"},
                },
            ],
            "session_id": "sess-001",
            "actor_id": "actor-001",
            "request_id": "req-001",
            "metadata": {"origin": "api-test"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["risk_score"] == 72
    assert body["risk_band"] == "high"
    assert body["incident"]["incident_id"] == "inc-001"
    assert body["incident"]["status"] == "action_required"
    assert body["incident"]["linked_reviews"] == ["rev-001"]
    assert body["recommended_playbooks"] == ["prompt-injection-containment"]
    assert service.calls[0]["session_id"] == "sess-001"
    assert service.calls[0]["actor_id"] == "actor-001"
    assert service.calls[0]["request_id"] == "req-001"
    assert service.calls[0]["metadata"] == {"origin": "api-test"}
    assert service.calls[0]["signals"][0]["evidence"]["tools"] == ["shell"]


def test_correlate_incidents_uses_query_fallbacks_for_session_and_actor():
    service = StubAttackCorrelationService()
    client = _build_client(service)

    response = client.post(
        "/incidents/correlate?session_id=sess-query&actor_id=actor-query",
        json={
            "signals": [
                {
                    "signal_id": "sig-002",
                    "signal_type": "artifact_download",
                    "source": "runtime_guard",
                    "severity": "medium",
                    "summary": "Downloaded suspicious artifact",
                    "evidence": {
                        "files": ["payload.py"],
                        "hashes": ["sha256:deadbeef"],
                    },
                },
            ],
        },
    )

    assert response.status_code == 200
    assert service.calls[0]["session_id"] == "sess-query"
    assert service.calls[0]["actor_id"] == "actor-query"


def test_correlate_incidents_rejects_empty_signal_list():
    service = StubAttackCorrelationService()
    client = _build_client(service)

    response = client.post(
        "/incidents/correlate",
        json={"signals": []},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "At least one signal is required for correlation",
    }
