from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes.alerts import router as alerts_router
from app.api.routes.audit import router as audit_router
from app.api.routes.dashboard import _build_install_key_views
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.deployment import router as deployment_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.onboarding import router as onboarding_router
from app.api.routes.organizations import router as organizations_router
from app.api.routes.policy import router as policy_router
from app.api.routes.quarantine import router as quarantine_router
from app.core.auth import AuthContext
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import get_install_key_registry
from app.dependencies.customer_auth import require_customer_read, require_customer_write
from app.services.policy_store import reset_policy_store
from routes import incidents as incidents_routes


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


def _dashboard_auth_context() -> AuthContext:
    return AuthContext(
        api_key=None,
        principal_type="customer",
        principal_id="customer-user-001",
        session_id=None,
        org_id=None,
        permissions=("customer:read", "customer:write"),
        roles=("customer_user",),
        authenticated=True,
        metadata={"email": "owner@ironclaw.local"},
    )


def _policy_settings_payload(default_decision: str) -> dict[str, object]:
    return {
        "mode": "lockdown",
        "default_decision": default_decision,
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
    }


def test_incidents_route_uses_canonical_review_queue_service() -> None:
    assert incidents_routes.ReviewQueueService.__module__ == "app.review.reviewqueueservice"
    assert incidents_routes._review_queue_service.__class__.__module__ == "app.review.reviewqueueservice"


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
        json=_policy_settings_payload("block"),
    )

    assert response.status_code == 200
    settings = response.json()["settings"]
    assert settings["mode"] == "lockdown"
    assert settings["default_decision"] == "block"


def test_policy_settings_default_to_block() -> None:
    reset_policy_store()
    try:
        client = TestClient(_build_test_app(), raise_server_exceptions=False)
        response = client.get("/policy/settings", headers=_headers())

        assert response.status_code == 200
        assert response.json()["settings"]["default_decision"] == "block"
    finally:
        reset_policy_store()


def test_policy_settings_reject_nonbinary_default_decisions() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    for default_decision in ("warn", "quarantine"):
        response = client.put(
            "/policy/settings",
            headers=_headers(),
            json=_policy_settings_payload(default_decision),
        )

        assert response.status_code == 422


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
    app = _build_test_app()
    app.dependency_overrides[require_customer_read] = _dashboard_auth_context
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/dashboard/overview", headers=_headers())

    assert response.status_code == 200
    data = response.json()
    assert len(data["kpis"]) >= 1
    assert data["alerts"] == []
    assert len(data["activity"]) >= 1
    assert data["metadata"]["wallet"]["owner_key"] == "owner@ironclaw.local"
    assert data["metadata"]["owner_key"] == "owner@ironclaw.local"
    assert data["metadata"]["install_key_dashboard"]["owner_key"] == "owner@ironclaw.local"
    assert len(data["metadata"]["install_key_dashboard"]["daily_usage"]) == 7


def test_dashboard_overview_rejects_caller_selected_owner() -> None:
    app = _build_test_app()
    app.dependency_overrides[require_customer_read] = _dashboard_auth_context
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get(
        "/dashboard/overview",
        headers=_headers(),
        params={"owner_key": "other@ironclaw.local"},
    )

    assert response.status_code == 403


def test_dashboard_units_rejects_caller_selected_owner() -> None:
    app = _build_test_app()
    app.dependency_overrides[require_customer_read] = _dashboard_auth_context
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get(
        "/dashboard/units",
        headers=_headers(),
        params={"owner_key": "other@ironclaw.local"},
    )

    assert response.status_code == 403


def test_dashboard_install_key_units_reflect_live_wallet_consumption() -> None:
    spec = next(s for s in InstallKeyFormatRegistry.list_specs() if s.program == "openclaw")
    record = SimpleNamespace(
        key_id="key-live-001",
        owner_key="owner@ironclaw.local",
        program="openclaw",
        masked_key=f"{spec.prefix}abcd****",
        label="",
        active=True,
        status="active",
        revoked_at=None,
        activated_at=None,
        created_at=None,
        last_used_at=None,
        units_consumed=0,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
    )
    wallet_usage = {"key-live-001": SimpleNamespace(total_consumed_units=7)}

    views = _build_install_key_views([record], "owner@ironclaw.local", wallet_usage)

    assert len(views) == len(InstallKeyFormatRegistry.list_programs())
    openclaw_view = next(view for view in views if view.program == "openclaw")
    assert openclaw_view.key_id == "key-live-001"
    assert openclaw_view.units_consumed == 7


def test_dashboard_usage_record_rejects_foreign_install_key() -> None:
    class ForeignInstallKeyRegistry:
        def get_key_by_id(self, key_id: str) -> SimpleNamespace:
            return SimpleNamespace(key_id=key_id, owner_key="other@ironclaw.local")

        def record_key_usage(self, key_id: str, *, units: int) -> None:
            raise AssertionError(f"foreign key usage must not be recorded: {key_id} ({units})")

    app = _build_test_app()
    app.dependency_overrides[require_customer_write] = _dashboard_auth_context
    app.dependency_overrides[get_install_key_registry] = ForeignInstallKeyRegistry
    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/dashboard/units/record",
        headers=_headers(),
        json={"key_id": "foreign-key-001", "units": 1},
    )

    assert response.status_code == 404


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
    assert guide["metadata"]["default_decision"] == "block"


def test_deployment_readiness_returns_checks() -> None:
    client = TestClient(_build_test_app(), raise_server_exceptions=False)

    response = client.get("/deployment/readiness", headers=_headers())

    assert response.status_code == 200
    readiness = response.json()["readiness"]
    assert readiness["overall_status"] in {"ready", "warning", "blocked"}
    assert len(readiness["checks"]) >= 1
