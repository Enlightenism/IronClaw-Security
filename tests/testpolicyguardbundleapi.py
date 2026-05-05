from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app


class _SignedBundle:
    def __init__(
        self,
        *,
        bundle_id: str = "bundle-001",
        version: str = "2026.04.25",
        algorithm: str = "hmac-sha256",
        digest: str = "a" * 64,
        signature: str = "signed-policy-bundle",
        manifest: dict[str, Any] | None = None,
    ) -> None:
        self.bundle_id = bundle_id
        self.version = version
        self.algorithm = algorithm
        self.digest = digest
        self.signature = signature
        self.manifest = manifest or {
            "bundleid": bundle_id,
            "version": version,
            "algorithm": algorithm,
            "digest": digest,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundleid": self.bundle_id,
            "version": self.version,
            "algorithm": self.algorithm,
            "digest": self.digest,
            "signature": self.signature,
            "manifest": dict(self.manifest),
        }


class _VerificationResult:
    def __init__(
        self,
        *,
        valid: bool = True,
        allowed: bool = True,
        verdict: str = "allow",
        bundle_id: str = "bundle-001",
        version: str = "2026.04.25",
        matched_rules: list[str] | None = None,
        reasons: list[dict[str, Any]] | None = None,
    ) -> None:
        self.valid = valid
        self.allowed = allowed
        self.verdict = verdict
        self.bundle_id = bundle_id
        self.version = version
        self.matched_rules = matched_rules or []
        self.reasons = reasons or []

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "allowed": self.allowed,
            "verdict": self.verdict,
            "bundleid": self.bundle_id,
            "version": self.version,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


class _BundleSigningServiceStub:
    def __init__(self) -> None:
        self.sign_result = _SignedBundle()
        self.verify_result = _VerificationResult()
        self.sign_calls: list[dict[str, Any]] = []
        self.verify_calls: list[dict[str, Any]] = []

    def sign_bundle(self, **kwargs: Any) -> _SignedBundle:
        self.sign_calls.append(dict(kwargs))
        return self.sign_result

    def verify_bundle(self, **kwargs: Any) -> _VerificationResult:
        self.verify_calls.append(dict(kwargs))
        return self.verify_result


class _PolicyStoreStub:
    def __init__(self) -> None:
        self.saved: list[dict[str, Any]] = []
        self.activated: list[dict[str, Any]] = []
        self.rollbacked: list[dict[str, Any]] = []
        self.current_bundle = {
            "bundleid": "bundle-001",
            "version": "2026.04.25",
            "status": "active",
        }
        self.history = [
            {"bundleid": "bundle-001", "version": "2026.04.24", "status": "retired"},
            {"bundleid": "bundle-001", "version": "2026.04.25", "status": "active"},
        ]

    def save_signed_bundle(self, **kwargs: Any) -> dict[str, Any]:
        self.saved.append(dict(kwargs))
        body = dict(kwargs)
        body.setdefault("bundleid", kwargs.get("bundle", {}).get("bundle_id", "bundle-001"))
        body.setdefault("version", kwargs.get("bundle", {}).get("version", "2026.04.25"))
        body.setdefault("status", "staged")
        return body

    def activate_bundle(self, **kwargs: Any) -> dict[str, Any]:
        self.activated.append(dict(kwargs))
        return {
            "bundleid": kwargs.get("bundle_id", "bundle-001"),
            "version": kwargs.get("version", "2026.04.25"),
            "status": "active",
        }

    def rollback_bundle(self, **kwargs: Any) -> dict[str, Any]:
        self.rollbacked.append(dict(kwargs))
        return {
            "bundleid": kwargs.get("bundle_id", "bundle-001"),
            "version": kwargs.get("target_version", "2026.04.24"),
            "status": "rolled_back",
        }

    def get_active_bundle(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self.current_bundle)

    def list_bundles(self, **kwargs: Any) -> list[dict[str, Any]]:
        return [dict(item) for item in self.history]


@pytest.fixture()
def api(monkeypatch):
    signing = _BundleSigningServiceStub()
    store = _PolicyStoreStub()

    monkeypatch.setattr(
        "app.api.policy.build_policy_bundle_signing_service",
        lambda: signing,
        raising=False,
    )
    monkeypatch.setattr(
        "app.api.policy.build_policy_store",
        lambda: store,
        raising=False,
    )
    monkeypatch.setattr(
        "app.api.releasepolicyroutes.build_policy_bundle_signing_service",
        lambda: signing,
        raising=False,
    )
    monkeypatch.setattr(
        "app.api.releasepolicyroutes.build_policy_store",
        lambda: store,
        raising=False,
    )

    return TestClient(app), signing, store


def _bundle_payload(version: str = "2026.04.25") -> dict[str, Any]:
    return {
        "bundle_id": "bundle-001",
        "version": version,
        "policy": {
            "default_verdict": "allow",
            "rules": [
                {"id": "safe-bash", "action": "allow", "match": {"tool": "bash"}},
                {"id": "high-risk", "action": "review", "match": {"risk": "high"}},
            ],
        },
        "metadata": {
            "issuer": "ironclaw",
            "targets": ["openclaw", "claude", "groq"],
        },
    }


def _post_first_existing(client: TestClient, paths: list[str], json: dict[str, Any]):
    last = None
    for path in paths:
        response = client.post(path, json=json)
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


def test_sign_bundle_api_returns_signed_bundle(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/sign", "/api/release-policy/bundles/sign"],
        {"bundle": _bundle_payload(), "secret": "ironclaw-secret"},
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.25"
    assert body["signature"] == "signed-policy-bundle"
    assert body["manifest"]["bundleid"] == "bundle-001"
    assert len(signing.sign_calls) == 1
    assert store.saved == []


def test_sign_bundle_api_rejects_missing_bundle(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/sign", "/api/release-policy/bundles/sign"],
        {"secret": "ironclaw-secret"},
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(signing.sign_calls) == 0


def test_verify_bundle_api_returns_valid_verification(api):
    client, signing, store = api
    signing.verify_result = _VerificationResult(
        valid=True,
        allowed=True,
        verdict="allow",
        matched_rules=["bundle:verified"],
    )

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/verify", "/api/release-policy/bundles/verify"],
        {
            "bundle": _bundle_payload(),
            "signature": "signed-policy-bundle",
            "secret": "ironclaw-secret",
            "manifest": {
                "bundleid": "bundle-001",
                "version": "2026.04.25",
                "algorithm": "hmac-sha256",
                "digest": "a" * 64,
            },
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["valid"] is True
    assert body["allowed"] is True
    assert body["verdict"] == "allow"
    assert "bundle:verified" in body["matchedrules"]
    assert len(signing.verify_calls) == 1


def test_verify_bundle_api_returns_blocked_verification(api):
    client, signing, store = api
    signing.verify_result = _VerificationResult(
        valid=False,
        allowed=False,
        verdict="block",
        matched_rules=["signature_mismatch"],
    )

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/verify", "/api/release-policy/bundles/verify"],
        {
            "bundle": _bundle_payload(),
            "signature": "bad-signature",
            "secret": "ironclaw-secret",
            "manifest": {
                "bundleid": "bundle-001",
                "version": "2026.04.25",
                "algorithm": "hmac-sha256",
                "digest": "a" * 64,
            },
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["valid"] is False
    assert body["allowed"] is False
    assert body["verdict"] in {"block", "reject"}
    assert "signature_mismatch" in body["matchedrules"]


def test_stage_bundle_api_signs_and_persists_bundle(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/stage", "/api/release-policy/bundles/stage"],
        {
            "bundle": _bundle_payload(),
            "secret": "ironclaw-secret",
            "activate": False,
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["status"] in {"staged", "saved"}
    assert len(signing.sign_calls) == 1
    assert len(store.saved) == 1
    assert store.saved[0]["bundle"]["bundle_id"] == "bundle-001"


def test_activate_bundle_api_promotes_staged_bundle(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/activate", "/api/release-policy/bundles/activate"],
        {"bundle_id": "bundle-001", "version": "2026.04.25"},
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.25"
    assert body["status"] == "active"
    assert len(store.activated) == 1


def test_rollback_bundle_api_rolls_back_target_version(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/rollback", "/api/release-policy/bundles/rollback"],
        {"bundle_id": "bundle-001", "target_version": "2026.04.24"},
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.24"
    assert body["status"] == "rolled_back"
    assert len(store.rollbacked) == 1


def test_get_active_bundle_api_returns_current_bundle(api):
    client, signing, store = api

    response, used_path = _get_first_existing(
        client,
        ["/api/policy/bundles/active", "/api/release-policy/bundles/active"],
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.25"
    assert body["status"] == "active"


def test_list_bundle_history_api_returns_versions(api):
    client, signing, store = api

    response, used_path = _get_first_existing(
        client,
        ["/api/policy/bundles", "/api/release-policy/bundles"],
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert isinstance(body, list)
    assert len(body) >= 2
    assert any(item["version"] == "2026.04.24" for item in body)
    assert any(item["status"] == "active" for item in body)


def test_stage_bundle_api_can_activate_immediately(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/stage", "/api/release-policy/bundles/stage"],
        {
            "bundle": _bundle_payload(),
            "secret": "ironclaw-secret",
            "activate": True,
        },
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert body["bundleid"] == "bundle-001"
    assert body["version"] == "2026.04.25"
    assert body["status"] in {"active", "staged"}
    assert len(signing.sign_calls) == 1
    assert len(store.saved) == 1


def test_verify_bundle_api_rejects_missing_signature(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/verify", "/api/release-policy/bundles/verify"],
        {
            "bundle": _bundle_payload(),
            "secret": "ironclaw-secret",
            "manifest": {
                "bundleid": "bundle-001",
                "version": "2026.04.25",
                "algorithm": "hmac-sha256",
                "digest": "a" * 64,
            },
        },
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(signing.verify_calls) == 0


def test_stage_bundle_api_rejects_missing_secret(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/stage", "/api/release-policy/bundles/stage"],
        {
            "bundle": _bundle_payload(),
            "activate": False,
        },
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(signing.sign_calls) == 0
    assert len(store.saved) == 0


def test_activate_bundle_api_requires_bundle_identity(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/activate", "/api/release-policy/bundles/activate"],
        {"version": "2026.04.25"},
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(store.activated) == 0


def test_rollback_bundle_api_requires_target_version(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/rollback", "/api/release-policy/bundles/rollback"],
        {"bundle_id": "bundle-001"},
    )

    assert response.status_code in {400, 422}, (used_path, response.text)
    assert len(store.rollbacked) == 0


def test_api_response_shapes_remain_json_serializable(api):
    client, signing, store = api

    response, used_path = _post_first_existing(
        client,
        ["/api/policy/bundles/sign", "/api/release-policy/bundles/sign"],
        {"bundle": _bundle_payload(), "secret": "ironclaw-secret"},
    )

    assert response.status_code == 200, (used_path, response.text)
    body = response.json()

    assert isinstance(body, dict)
    assert isinstance(body["manifest"], dict)
    assert isinstance(body["signature"], str)
    assert isinstance(body["digest"], str)