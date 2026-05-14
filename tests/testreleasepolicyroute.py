from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app


class _ReleasePolicyServiceStub:
    def __init__(self) -> None:
        self.evaluate_result: dict[str, Any] = {
            "allowed": True,
            "enabled": True,
            "verdict": "allow",
            "matchedrules": ["rollout:enabled"],
            "reasons": [],
        }
        self.put_result: dict[str, Any] = {
            "policyid": "release-policy-001",
            "runtime": "openclaw",
            "environment": "prod",
            "rolloutpercent": 100,
            "enabled": True,
            "mode": "enforce",
        }
        self.override_result: dict[str, Any] = {
            "overrideid": "override-001",
            "runtime": "claude",
            "action": "allow",
            "active": True,
            "scope": "organization",
        }
        self.rollback_result: dict[str, Any] = {
            "policyid": "release-policy-001",
            "runtime": "openclaw",
            "environment": "prod",
            "rolledbackto": "2026.04.24",
            "status": "rolled_back",
        }
        self.current_policy: dict[str, Any] = {
            "policyid": "release-policy-001",
            "runtime": "openclaw",
            "environment": "prod",
            "rolloutpercent": 25,
            "enabled": True,
            "mode": "observe",
        }
        self.history: list[dict[str, Any]] = [
            {
                "policyid": "release-policy-001",
                "runtime": "openclaw",
                "environment": "prod",
                "rolloutpercent": 10,
                "enabled": True,
                "mode": "observe",
                "version": "2026.04.24",
            },
            {
                "policyid": "release-policy-001",
                "runtime": "openclaw",
                "environment": "prod",
                "rolloutpercent": 25,
                "enabled": True,
                "mode": "observe",
                "version": "2026.04.25",
            },
        ]
        self.evaluate_calls: list[dict[str, Any]] = []
        self.put_calls: list[dict[str, Any]] = []
        self.override_calls: list[dict[str, Any]] = []
        self.rollback_calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any):
        self.evaluate_calls.append(dict(kwargs))

        class _Result:
            def __init__(self, body: dict[str, Any]) -> None:
                self.body = body

            def as_dict(self) -> dict[str, Any]:
                return dict(self.body)

        return _Result(self.evaluate_result)

    def save_release_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.put_calls.append(dict(kwargs))
        return dict(self.put_result)

    def save_override(self, **kwargs: Any) -> dict[str, Any]:
        self.override_calls.append(dict(kwargs))
        return dict(self.override_result)

    def rollback_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.rollback_calls.append(dict(kwargs))
        return dict(self.rollback_result)

    def get_release_policy(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self.current_policy)

    def list_release_policies(self, **kwargs: Any) -> list[dict[str, Any]]:
        return [dict(item) for item in self.history]


@pytest.fixture
def api(monkeypatch):
    service = _ReleasePolicyServiceStub()

    monkeypatch.setattr(
        "app.api.release_policy_routes.build_release_policy_service",
        lambda: service,
        raising=False,
    )
    monkeypatch.setattr(
        "app.services.release_policy.build_release_policy_service",
        lambda: service,
        raising=False,
    )

    return TestClient(app), service


def _post_first_existing(client: TestClient, paths: list[str], json: dict[str, Any]):
    last = None
    for path in paths:
        response = client.post(path, json=json)
        if response.status_code != 404:
            return response, path
        last = response
    return last, paths[-1]


def _put_first_existing(client: TestClient, paths: list[str], json: dict[str, Any]):
    last = None
    for path in paths:
        response = client.put(path, json=json)
        if response.status_code != 404:
            return response, path
        last = response
    return last, paths[-1]


def _get_first_existing(client: TestClient, paths: list[str]):
    last = None
    for path in paths:
        response = client.get(path)
        if response.status_code != 404:
            return response, path
        last = response
    return last, paths[-1]


def test_evaluate_release_policy_route_allows_enabled_rollout(api):
    client, service = api
    service.evaluate_result = {
        "allowed": True,
        "enabled": True,
        "verdict": "allow",
        "matchedrules": ["rollout:enabled", "runtime:openclaw"],
        "reasons": [],
    }

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/evaluate", "/api/policy/release/evaluate"],
        {
            "runtime": "openclaw",
            "environment": "prod",
            "action": "execute",
            "context": {"organization_id": "org-001"},
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["allowed"] is True
    assert body["enabled"] is True
    assert body["verdict"] == "allow"
    assert "rollout:enabled" in body["matchedrules"]
    assert len(service.evaluate_calls) == 1


def test_evaluate_release_policy_route_blocks_disabled_rollout(api):
    client, service = api
    service.evaluate_result = {
        "allowed": False,
        "enabled": False,
        "verdict": "block",
        "matchedrules": ["rollout:disabled"],
        "reasons": [{"label": "Disabled", "details": "Policy rollout disabled"}],
    }

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/evaluate", "/api/policy/release/evaluate"],
        {
            "runtime": "claude",
            "environment": "prod",
            "action": "execute",
            "context": {"organization_id": "org-001"},
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["allowed"] is False
    assert body["enabled"] is False
    assert body["verdict"] == "block"
    assert "rollout:disabled" in body["matchedrules"]


def test_put_release_policy_route_saves_rollout_controls(api):
    client, service = api
    service.put_result = {
        "policyid": "release-policy-001",
        "runtime": "openclaw",
        "environment": "prod",
        "rolloutpercent": 25,
        "enabled": True,
        "mode": "observe",
    }

    response, used_path = _put_first_existing(
        client,
        ["/api/release-policy", "/api/policy/release"],
        {
            "runtime": "openclaw",
            "environment": "prod",
            "rollout_percent": 25,
            "enabled": True,
            "mode": "observe",
            "bundle_id": "bundle-001",
            "bundle_version": "2026.04.25",
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["policyid"] == "release-policy-001"
    assert body["runtime"] == "openclaw"
    assert body["environment"] == "prod"
    assert body["rolloutpercent"] == 25
    assert body["mode"] == "observe"
    assert len(service.put_calls) == 1


def test_put_release_policy_route_rejects_invalid_rollout_percent(api):
    client, service = api

    response, used_path = _put_first_existing(
        client,
        ["/api/release-policy", "/api/policy/release"],
        {
            "runtime": "openclaw",
            "environment": "prod",
            "rollout_percent": 101,
            "enabled": True,
            "mode": "observe",
        },
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(service.put_calls) == 0


def test_put_release_policy_route_rejects_missing_runtime(api):
    client, service = api

    response, used_path = _put_first_existing(
        client,
        ["/api/release-policy", "/api/policy/release"],
        {
            "environment": "prod",
            "rollout_percent": 25,
            "enabled": True,
            "mode": "observe",
        },
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(service.put_calls) == 0


def test_create_override_route_saves_override(api):
    client, service = api
    service.override_result = {
        "overrideid": "override-777",
        "runtime": "groq",
        "action": "block",
        "active": True,
        "scope": "organization",
        "reason": "emergency containment",
    }

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/overrides", "/api/policy/release/overrides"],
        {
            "runtime": "groq",
            "environment": "prod",
            "action": "block",
            "scope": "organization",
            "scope_id": "org-001",
            "reason": "emergency containment",
            "active": True,
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["overrideid"] == "override-777"
    assert body["runtime"] == "groq"
    assert body["action"] == "block"
    assert body["active"] is True
    assert len(service.override_calls) == 1


def test_create_override_route_rejects_missing_action(api):
    client, service = api

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/overrides", "/api/policy/release/overrides"],
        {
            "runtime": "groq",
            "environment": "prod",
            "scope": "organization",
            "scope_id": "org-001",
            "active": True,
        },
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(service.override_calls) == 0


def test_get_release_policy_route_returns_current_policy(api):
    client, service = api
    service.current_policy = {
        "policyid": "release-policy-001",
        "runtime": "claude",
        "environment": "prod",
        "rolloutpercent": 50,
        "enabled": True,
        "mode": "enforce",
    }

    response, used_path = _get_first_existing(
        client,
        ["/api/release-policy/current", "/api/policy/release/current"],
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["policyid"] == "release-policy-001"
    assert body["runtime"] == "claude"
    assert body["rolloutpercent"] == 50
    assert body["mode"] == "enforce"


def test_list_release_policy_history_route_returns_versions(api):
    client, service = api

    response, used_path = _get_first_existing(
        client,
        ["/api/release-policy/history", "/api/policy/release/history"],
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert isinstance(body, list)
    assert len(body) >= 2
    assert any(item["version"] == "2026.04.24" for item in body)
    assert any(item["rolloutpercent"] == 25 for item in body)


def test_rollback_release_policy_route_rolls_back_version(api):
    client, service = api
    service.rollback_result = {
        "policyid": "release-policy-001",
        "runtime": "openclaw",
        "environment": "prod",
        "rolledbackto": "2026.04.24",
        "status": "rolled_back",
    }

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/rollback", "/api/policy/release/rollback"],
        {
            "runtime": "openclaw",
            "environment": "prod",
            "target_version": "2026.04.24",
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["policyid"] == "release-policy-001"
    assert body["runtime"] == "openclaw"
    assert body["rolledbackto"] == "2026.04.24"
    assert body["status"] == "rolled_back"
    assert len(service.rollback_calls) == 1


def test_rollback_release_policy_route_requires_target_version(api):
    client, service = api

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/rollback", "/api/policy/release/rollback"],
        {
            "runtime": "openclaw",
            "environment": "prod",
        },
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(service.rollback_calls) == 0


@pytest.mark.parametrize("runtime", ["openclaw", "claude", "groq", "future-runtime"])
def test_evaluate_route_supports_cross_platform_runtimes(api, runtime: str):
    client, service = api
    service.evaluate_result = {
        "allowed": True,
        "enabled": True,
        "verdict": "allow",
        "matchedrules": [f"runtime:{runtime}"],
        "reasons": [],
    }

    response, used_path = _post_first_existing(
        client,
        ["/api/release-policy/evaluate", "/api/policy/release/evaluate"],
        {
            "runtime": runtime,
            "environment": "prod",
            "action": "execute",
            "context": {"organization_id": "org-001"},
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert body["allowed"] is True
    assert f"runtime:{runtime}" in body["matchedrules"]
    assert service.evaluate_calls[-1]["runtime"] == runtime


def test_route_outputs_remain_json_serializable(api):
    client, service = api

    response, used_path = _put_first_existing(
        client,
        ["/api/release-policy", "/api/policy/release"],
        {
            "runtime": "openclaw",
            "environment": "prod",
            "rollout_percent": 10,
            "enabled": True,
            "mode": "observe",
            "bundle_id": "bundle-001",
            "bundle_version": "2026.04.25",
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()
    assert isinstance(body, dict)
    assert isinstance(body["policyid"], str)
    assert isinstance(body["rolloutpercent"], int)
    assert isinstance(body["enabled"], bool)
