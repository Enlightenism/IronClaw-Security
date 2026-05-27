from __future__ import annotations

from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.ui import UI_ROUTERS, get_ui_routers, include_ui_routers, iter_ui_routers
from app.ui.activity.clientprofile import router as client_profile_router
from app.ui.activity.clientsession import router as client_session_activity_router
from app.ui.activity.sessiontimeline import router as session_timeline_router
from app.ui.admin.operators import router as operator_management_router
from app.ui.admin.roles import router as access_control_roles_router
from app.ui.alerts.notifications import router as alert_notifications_router
from app.ui.audit.log import router as audit_log_router
from app.ui.billing.invoice_detail import router as billing_invoice_detail_router
from app.ui.billing.invoices import router as billing_invoices_router
from app.ui.billing.package import router as billing_package_router
from app.ui.billing.payment_methods import router as billing_payment_methods_router
from app.ui.billing.plan_change import router as billing_plan_change_router
from app.ui.billing_index import router as billing_index_router
from app.ui.billing_manifest import router as billing_manifest_router
from app.ui.billing_registry import router as billing_registry_router
from app.ui.billing_summary import router as billing_summary_router
from app.ui.billing_wallet import router as billing_wallet_router
from app.ui.customer_key_detail import router as customer_key_detail_router
from app.ui.customer_keys import router as customer_keys_router
from app.ui.docs.api_reference import router as docs_api_reference_router
from app.ui.docs.authentication import router as docs_authentication_router
from app.ui.docs.changelog import router as docs_changelog_router
from app.ui.docs.policy_guide import router as docs_policy_guide_router
from app.ui.docs.quickstart import router as docs_quickstart_router
from app.ui.docs.telemetry_guide import router as docs_telemetry_guide_router
from app.ui.docs.webhooks import router as docs_webhooks_router
from app.ui.executions.dashboard import router as execution_dashboard_router
from app.ui.executions.detail import router as execution_detail_router
from app.ui.executions.explorer import router as execution_explorer_router
from app.ui.executions.testconsole import router as execution_test_console_router
from app.ui.groq import router as groq_ui_router
from app.ui.health_snapshot import router as health_snapshot_router
from app.ui.incidents.triage import router as incident_triage_router
from app.ui.insights.policy import router as policy_insights_router
from app.ui.integrations.settings import router as integration_settings_router
from app.ui.metrics_summary import router as metrics_summary_router
from app.ui.organizations import router as organizations_router
from app.ui.request_context import router as request_context_router
from app.ui.reviews.detail import router as review_detail_router
from app.ui.reviews.queue import router as review_queue_router
from app.ui.runtime.status import router as runtime_status_router
from app.ui.settings.configuration import router as settings_configuration_router
from app.ui.system.diagnostics import router as system_diagnostics_router
from app.ui.telemetry_access_summary import router as telemetry_access_summary_router
from app.ui.usage_event_detail import router as usage_event_detail_router
from app.ui.usage_reports import router as usage_reports_router

_EXPECTED_ROUTERS: tuple[APIRouter, ...] = (
    organizations_router,
    execution_dashboard_router,
    execution_detail_router,
    review_queue_router,
    review_detail_router,
    policy_insights_router,
    client_session_activity_router,
    client_profile_router,
    session_timeline_router,
    execution_explorer_router,
    settings_configuration_router,
    runtime_status_router,
    audit_log_router,
    execution_test_console_router,
    alert_notifications_router,
    system_diagnostics_router,
    integration_settings_router,
    incident_triage_router,
    operator_management_router,
    access_control_roles_router,
    groq_ui_router,
    billing_manifest_router,
    billing_registry_router,
    billing_index_router,
    billing_summary_router,
    billing_wallet_router,
    billing_invoices_router,
    billing_invoice_detail_router,
    billing_payment_methods_router,
    billing_plan_change_router,
    billing_package_router,
    usage_reports_router,
    usage_event_detail_router,
    telemetry_access_summary_router,
    metrics_summary_router,
    health_snapshot_router,
    customer_keys_router,
    customer_key_detail_router,
    request_context_router,
    docs_quickstart_router,
    docs_api_reference_router,
    docs_authentication_router,
    docs_policy_guide_router,
    docs_telemetry_guide_router,
    docs_webhooks_router,
    docs_changelog_router,
)


# ---------------------------------------------------------------------------
# UI_ROUTERS contract
# ---------------------------------------------------------------------------


def test_ui_routers_is_tuple() -> None:
    assert isinstance(UI_ROUTERS, tuple)


def test_ui_routers_is_non_empty() -> None:
    assert len(UI_ROUTERS) > 0


def test_ui_routers_all_elements_are_apirouters() -> None:
    for i, ui_router in enumerate(UI_ROUTERS):
        assert isinstance(ui_router, APIRouter), f"UI_ROUTERS[{i}] is not an APIRouter"


def test_ui_routers_contains_root_ui_router() -> None:
    from app.ui import router as root_ui_router

    assert root_ui_router in UI_ROUTERS


def test_ui_routers_root_router_prefix_is_ui() -> None:
    from app.ui import router as root_ui_router

    assert root_ui_router.prefix == "/ui"


def test_ui_routers_root_router_has_ui_tag() -> None:
    from app.ui import router as root_ui_router

    assert "ui" in (root_ui_router.tags or [])


def test_ui_routers_length_matches_expected() -> None:
    # root router + all sub-routers
    assert len(UI_ROUTERS) == len(_EXPECTED_ROUTERS) + 1


def test_ui_routers_contains_all_expected_sub_routers() -> None:
    for expected in _EXPECTED_ROUTERS:
        assert expected in UI_ROUTERS, f"UI_ROUTERS missing router with prefix {expected.prefix!r}"


def test_ui_routers_no_duplicate_router_objects() -> None:
    assert len(UI_ROUTERS) == len(set(id(r) for r in UI_ROUTERS))


# ---------------------------------------------------------------------------
# get_ui_routers()
# ---------------------------------------------------------------------------


def test_get_ui_routers_returns_tuple() -> None:
    result = get_ui_routers()
    assert isinstance(result, tuple)


def test_get_ui_routers_returns_same_object_as_ui_routers() -> None:
    assert get_ui_routers() is UI_ROUTERS


def test_get_ui_routers_length_matches_ui_routers() -> None:
    assert len(get_ui_routers()) == len(UI_ROUTERS)


# ---------------------------------------------------------------------------
# iter_ui_routers()
# ---------------------------------------------------------------------------


def test_iter_ui_routers_is_iterable() -> None:
    result = list(iter_ui_routers())
    assert len(result) > 0


def test_iter_ui_routers_all_elements_are_apirouters() -> None:
    for i, ui_router in enumerate(iter_ui_routers()):
        assert isinstance(ui_router, APIRouter), f"iter_ui_routers()[{i}] is not an APIRouter"


def test_iter_ui_routers_yields_same_routers_as_ui_routers() -> None:
    assert list(iter_ui_routers()) == list(UI_ROUTERS)


# ---------------------------------------------------------------------------
# include_ui_routers()
# ---------------------------------------------------------------------------


def test_include_ui_routers_registers_all_routers_on_fresh_app() -> None:
    from fastapi import FastAPI

    app = FastAPI()
    include_ui_routers(app)
    registered_prefixes = {route.path for route in app.routes}
    assert len(registered_prefixes) > 0


def test_includeuirouters_alias_works() -> None:
    from fastapi import FastAPI

    from app.ui import includeuirouters

    app = FastAPI()
    includeuirouters(app)
    assert len(app.routes) > 0


# ---------------------------------------------------------------------------
# docs sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_docs_quickstart_router() -> None:
    assert docs_quickstart_router in UI_ROUTERS


def test_ui_routers_contains_docs_api_reference_router() -> None:
    assert docs_api_reference_router in UI_ROUTERS


def test_ui_routers_contains_docs_authentication_router() -> None:
    assert docs_authentication_router in UI_ROUTERS


def test_ui_routers_contains_docs_policy_guide_router() -> None:
    assert docs_policy_guide_router in UI_ROUTERS


def test_ui_routers_contains_docs_telemetry_guide_router() -> None:
    assert docs_telemetry_guide_router in UI_ROUTERS


def test_ui_routers_contains_docs_webhooks_router() -> None:
    assert docs_webhooks_router in UI_ROUTERS


def test_ui_routers_contains_docs_changelog_router() -> None:
    assert docs_changelog_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# billing sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_billing_manifest_router() -> None:
    assert billing_manifest_router in UI_ROUTERS


def test_ui_routers_contains_billing_registry_router() -> None:
    assert billing_registry_router in UI_ROUTERS


def test_ui_routers_contains_billing_index_router() -> None:
    assert billing_index_router in UI_ROUTERS


def test_ui_routers_contains_billing_summary_router() -> None:
    assert billing_summary_router in UI_ROUTERS


def test_ui_routers_contains_billing_wallet_router() -> None:
    assert billing_wallet_router in UI_ROUTERS


def test_ui_routers_contains_billing_invoices_router() -> None:
    assert billing_invoices_router in UI_ROUTERS


def test_ui_routers_contains_billing_invoice_detail_router() -> None:
    assert billing_invoice_detail_router in UI_ROUTERS


def test_ui_routers_contains_billing_payment_methods_router() -> None:
    assert billing_payment_methods_router in UI_ROUTERS


def test_ui_routers_contains_billing_plan_change_router() -> None:
    assert billing_plan_change_router in UI_ROUTERS


def test_ui_routers_contains_billing_package_router() -> None:
    assert billing_package_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# guard/execution sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_execution_dashboard_router() -> None:
    assert execution_dashboard_router in UI_ROUTERS


def test_ui_routers_contains_execution_detail_router() -> None:
    assert execution_detail_router in UI_ROUTERS


def test_ui_routers_contains_execution_explorer_router() -> None:
    assert execution_explorer_router in UI_ROUTERS


def test_ui_routers_contains_execution_test_console_router() -> None:
    assert execution_test_console_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# review sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_review_queue_router() -> None:
    assert review_queue_router in UI_ROUTERS


def test_ui_routers_contains_review_detail_router() -> None:
    assert review_detail_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# admin sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_operator_management_router() -> None:
    assert operator_management_router in UI_ROUTERS


def test_ui_routers_contains_access_control_roles_router() -> None:
    assert access_control_roles_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# activity sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_client_profile_router() -> None:
    assert client_profile_router in UI_ROUTERS


def test_ui_routers_contains_client_session_activity_router() -> None:
    assert client_session_activity_router in UI_ROUTERS


def test_ui_routers_contains_session_timeline_router() -> None:
    assert session_timeline_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# remaining sub-routers present
# ---------------------------------------------------------------------------


def test_ui_routers_contains_organizations_router() -> None:
    assert organizations_router in UI_ROUTERS


def test_ui_routers_contains_policy_insights_router() -> None:
    assert policy_insights_router in UI_ROUTERS


def test_ui_routers_contains_settings_configuration_router() -> None:
    assert settings_configuration_router in UI_ROUTERS


def test_ui_routers_contains_runtime_status_router() -> None:
    assert runtime_status_router in UI_ROUTERS


def test_ui_routers_contains_audit_log_router() -> None:
    assert audit_log_router in UI_ROUTERS


def test_ui_routers_contains_alert_notifications_router() -> None:
    assert alert_notifications_router in UI_ROUTERS


def test_ui_routers_contains_system_diagnostics_router() -> None:
    assert system_diagnostics_router in UI_ROUTERS


def test_ui_routers_contains_integration_settings_router() -> None:
    assert integration_settings_router in UI_ROUTERS


def test_ui_routers_contains_incident_triage_router() -> None:
    assert incident_triage_router in UI_ROUTERS


def test_ui_routers_contains_groq_ui_router() -> None:
    assert groq_ui_router in UI_ROUTERS


def test_ui_routers_contains_usage_reports_router() -> None:
    assert usage_reports_router in UI_ROUTERS


def test_ui_routers_contains_usage_event_detail_router() -> None:
    assert usage_event_detail_router in UI_ROUTERS


def test_ui_routers_contains_telemetry_access_summary_router() -> None:
    assert telemetry_access_summary_router in UI_ROUTERS


def test_ui_routers_contains_metrics_summary_router() -> None:
    assert metrics_summary_router in UI_ROUTERS


def test_ui_routers_contains_health_snapshot_router() -> None:
    assert health_snapshot_router in UI_ROUTERS


def test_ui_routers_contains_customer_keys_router() -> None:
    assert customer_keys_router in UI_ROUTERS


def test_ui_routers_contains_customer_key_detail_router() -> None:
    assert customer_key_detail_router in UI_ROUTERS


def test_ui_routers_contains_request_context_router() -> None:
    assert request_context_router in UI_ROUTERS


# ---------------------------------------------------------------------------
# GET /ui/status route
# ---------------------------------------------------------------------------


def test_ui_status_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    assert response.status_code == 200


def test_ui_status_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    assert "application/json" in response.headers.get("content-type", "")


def test_ui_status_response_is_object(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    assert isinstance(response.json(), dict)


def test_ui_status_has_status_field_ok(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    assert response.json()["status"] == "ok"


def test_ui_status_has_total_routers_field(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    body = response.json()
    assert "total_routers" in body
    assert isinstance(body["total_routers"], int)
    assert body["total_routers"] > 0


def test_ui_status_total_routers_matches_ui_routers_length(
    test_client: TestClient,
) -> None:
    response = test_client.get("/ui/status")
    assert response.json()["total_routers"] == len(UI_ROUTERS)


def test_ui_status_has_routers_list(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    body = response.json()
    assert "routers" in body
    assert isinstance(body["routers"], list)
    assert len(body["routers"]) > 0


def test_ui_status_routers_list_length_matches_total_routers(
    test_client: TestClient,
) -> None:
    response = test_client.get("/ui/status")
    body = response.json()
    assert len(body["routers"]) == body["total_routers"]


def test_ui_status_each_router_entry_has_prefix_and_tags(
    test_client: TestClient,
) -> None:
    response = test_client.get("/ui/status")
    for i, entry in enumerate(response.json()["routers"]):
        assert "prefix" in entry, f"routers[{i}] missing 'prefix'"
        assert "tags" in entry, f"routers[{i}] missing 'tags'"
        assert isinstance(entry["prefix"], str), f"routers[{i}].prefix must be str"
        assert isinstance(entry["tags"], list), f"routers[{i}].tags must be list"


def test_ui_status_root_router_prefix_present_in_routers_list(
    test_client: TestClient,
) -> None:
    response = test_client.get("/ui/status")
    prefixes = [e["prefix"] for e in response.json()["routers"]]
    assert "/ui" in prefixes


def test_ui_status_docs_prefixes_present_in_routers_list(
    test_client: TestClient,
) -> None:
    response = test_client.get("/ui/status")
    prefixes = [e["prefix"] for e in response.json()["routers"]]
    assert "/ui/docs" in prefixes


def test_ui_status_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get("/ui/status")
    assert response.status_code != 401
    assert response.status_code != 403


# ---------------------------------------------------------------------------
# GET /billing-manifest route (manifest route smoke test)
# ---------------------------------------------------------------------------


def test_billing_manifest_returns_200(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.status_code == 200


def test_billing_manifest_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert "application/json" in response.headers.get("content-type", "")


def test_billing_manifest_response_is_object(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert isinstance(response.json(), dict)


def test_billing_manifest_status_is_ok(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["status"] == "ok"


def test_billing_manifest_service_is_ironclaw(test_client: TestClient) -> None:
    response = test_client.get("/billing-manifest")
    assert response.json()["service"] == "IronClaw-Security"
