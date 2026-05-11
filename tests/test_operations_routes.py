from __future__ import annotations


from fastapi import FastAPI
from fastapi.testclient import TestClient


from app.api.routes.alerts import router as alerts_router
from app.api.routes.audit import router as audit_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.deployment import router as deployment_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.onboarding import router as onboarding_router
from app.api.routes.organizations import router as organizations_router
from app.api.routes.policy import router as policy_router
from app.api.routes.quarantine import router as quarantine_router


def _build_test_app() -> FastAPI:
    app = FastAPI()
    app.state.settings = type(
        "TestSettings",
        (),
        {
            "auth_required": True,
            "api_key": "test-key",
            "admin_api_key": "",
        },
    )()
    app.include_router(incidents_router)
    app.include_router(quarantine_router)
    app.include_router(audit_router)
    app.include_router(policy_router)
    app.include_router(organizations_router)
    app.include_router(dashboard_router)
    app.include_router(alerts_router)
    app.include_router(onboarding_router)
    app.include_router(deployment_router)
    return app


def _headers() -> dict[str, str]:
    return {"X-API-Key": "test-key"}


def test_incidents_route_lists_items() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=True)

    response = client.get("/incidents/", headers=_headers())

    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1


def test_quarantine_release_flow_updates_status() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    list_response = client.get("/quarantine/", headers=_headers())
    assert list_response.status_code == 200
    quarantine_id = list_response.json()["items"][0]["quarantine_id"]

    release_response = client.post(
        f"/quarantine/{quarantine_id}/release",
        headers=_headers(),
        json={
            "release_reason": "false positive confirmed",
            "released_by": "analyst@ironclaw.local",
        },
    )

    assert release_response.status_code == 200
    item = release_response.json()["item"]
    assert item["status"] == "released"
    assert item["release_reason"] == "false positive confirmed"


def test_audit_events_can_be_filtered_by_actor_request_and_trace() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    all_response = client.get("/audit/events", headers=_headers())
    assert all_response.status_code == 200
    event = all_response.json()["items"][0]

    actor_response = client.get(
        f"/audit/events/by-actor/{event['actor_id']}",
        headers=_headers(),
    )
    assert actor_response.status_code == 200
    assert len(actor_response.json()) >= 1

    request_response = client.get(
        f"/audit/events/by-request/{event['request_id']}",
        headers=_headers(),
    )
    assert request_response.status_code == 200
    assert len(request_response.json()) >= 1

    trace_response = client.get(
        f"/audit/events/by-trace/{event['trace_id']}",
        headers=_headers(),
    )
    assert trace_response.status_code == 200
    assert len(trace_response.json()) >= 1


def test_policy_settings_can_be_updated() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.put(
        "/policy/settings",
        headers=_headers(),
        json={
            "mode": "lockdown",
            "default_decision": "block",
            "require_human_review_for_quarantine": True,
            "sandbox_all_untrusted_content": True,
            "block_high_risk_tool_calls": True,
            "strict_prompt_ingress": True,
            "thresholds": {
                "prompt_injection_score": 0.9,
                "malware_score": 0.8,
                "exfiltration_score": 0.7,
                "tool_abuse_score": 0.85,
            },
            "metadata": {"updated_by": "test-suite"},
        },
    )

    assert response.status_code == 200
    settings = response.json()["settings"]
    assert settings["mode"] == "lockdown"
    assert settings["default_decision"] == "block"


def test_organizations_flow_creates_org_and_member() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    create_response = client.post(
        "/organizations/",
        headers=_headers(),
        json={
            "name": "IronClaw Labs",
            "slug": "ironclaw-labs",
            "owner_email": "owner@ironclaw.local",
            "owner_display_name": "Owner",
            "metadata": {"plan": "team-security"},
        },
    )

    assert create_response.status_code == 201
    organization = create_response.json()["organization"]
    organization_id = organization["organization_id"]
    assert organization["slug"] == "ironclaw-labs"

    member_response = client.post(
        f"/organizations/{organization_id}/members",
        headers=_headers(),
        json={
            "email": "analyst@ironclaw.local",
            "display_name": "Analyst",
            "role": "analyst",
            "metadata": {"invited_by": "owner@ironclaw.local"},
        },
    )

    assert member_response.status_code == 201
    updated_org = member_response.json()["organization"]
    assert len(updated_org["members"]) == 2


def test_dashboard_overview_returns_expected_sections() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/dashboard/overview", headers=_headers())

    assert response.status_code == 200
    data = response.json()
    assert len(data["kpis"]) >= 1
    assert len(data["alerts"]) >= 1
    assert len(data["activity"]) >= 1
    assert data["metadata"]["wallet"]["owner_key"] == "demo@ironclaw.local"


def test_alert_endpoint_create_and_update_flow() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    create_response = client.post(
        "/alerts/endpoints",
        headers=_headers(),
        json={
            "channel": "email",
            "name": "Security Mailbox",
            "target": "soc@ironclaw.local",
            "subscribed_events": ["incident_created", "quarantine_created"],
            "metadata": {"team": "soc"},
        },
    )

    assert create_response.status_code == 201
    endpoint = create_response.json()["endpoint"]
    endpoint_id = endpoint["endpoint_id"]

    update_response = client.put(
        f"/alerts/endpoints/{endpoint_id}",
        headers=_headers(),
        json={
            "subscribed_events": ["incident_created", "incident_updated"],
            "status": "paused",
            "metadata": {"updated_by": "test-suite"},
        },
    )

    assert update_response.status_code == 200
    updated_endpoint = update_response.json()["endpoint"]
    assert updated_endpoint["status"] == "paused"


def test_onboarding_quickstart_returns_steps_and_integrations() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/onboarding/quickstart", headers=_headers())

    assert response.status_code == 200
    guide = response.json()["guide"]
    assert len(guide["steps"]) >= 1
    assert len(guide["integrations"]) >= 1


def test_deployment_readiness_returns_checks() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/deployment/readiness", headers=_headers())

    assert response.status_code == 200
    readiness = response.json()["readiness"]
    assert readiness["overall_status"] in {"ready", "warning", "blocked"}
    assert len(readiness["checks"]) >= 1