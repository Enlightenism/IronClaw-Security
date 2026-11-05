from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
import pytest

from app.api import install_gate as install_gate_api
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.runtime import install_gate
from app.runtime.install_gate import InstallGateDecision
from app.services.third_party_install_scanner import ScanOutcome

BASE = "/install-gate"
_TOKEN = "ic_claim_" + "C" * 32
_CANONICAL_OPENCLAW = InstallKeyFormatRegistry.get_spec("openclaw").format_command(_TOKEN)
_REQUEST = {"platform": "openclaw", "command": _CANONICAL_OPENCLAW}


@pytest.fixture(autouse=True)
def _silence_telemetry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(install_gate, "append_telemetry_event", lambda *_args, **_kwargs: None)


@pytest.fixture(autouse=True)
def _block_third_party_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        install_gate,
        "scan_third_party_install",
        lambda *_args, **_kwargs: ScanOutcome(False, ["unresolvable_install_source"], []),
    )


def test_pinned_command_response_shape_and_allow(test_client: TestClient) -> None:
    r = test_client.post(f"{BASE}/evaluate", json=_REQUEST)

    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"verdict", "family", "program", "pinned", "reasons", "artifacts"}
    assert body["verdict"] == "allow"
    assert body["family"] == "ironclaw_installer"
    assert body["program"] == "openclaw"
    assert body["pinned"] is True
    assert body["reasons"] == ["pinned_install_command"]
    assert body["artifacts"] == []
    assert _TOKEN not in r.text


def test_unpinned_command_is_blocked(test_client: TestClient) -> None:
    r = test_client.post(f"{BASE}/evaluate", json={"platform": "openclaw", "command": "pip install requests"})

    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "block"
    assert body["family"] == "pip"
    assert body["program"] is None
    assert body["pinned"] is False
    assert body["reasons"] == ["unresolvable_install_source"]


def test_route_forwards_agent_and_client_ids(test_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, Any]] = []

    def _stub(command: str, **kwargs: Any) -> InstallGateDecision:
        captured.append({"command": command, **kwargs})
        return InstallGateDecision("block", "unknown", None, False, ["not_pinned"])

    monkeypatch.setattr(install_gate_api, "evaluate_install_command", _stub)

    r = test_client.post(f"{BASE}/evaluate", json={"platform": "goose", "command": "goose run", "agent_id": "ag-1", "client_id": "cl-1"})

    assert r.status_code == 200
    assert len(captured) == 1
    assert {key: value for key, value in captured[0].items() if key != "owner_key"} == {"command": "goose run", "platform": "goose", "agent_id": "ag-1", "client_id": "cl-1"}


class _StubInstallKeyRegistry:
    def authenticate_install_key(self, candidate: str) -> SimpleNamespace:
        return SimpleNamespace(key_id="key-1", owner_key="owner-1", program="openclaw")


def test_install_key_scopes_owner_for_matching_platform(test_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr("app.core.install_keys.get_install_key_registry", lambda: _StubInstallKeyRegistry())

    def _stub(command: str, **kwargs: Any) -> InstallGateDecision:
        captured.append(kwargs)
        return InstallGateDecision("block", "unknown", None, False, ["not_pinned"])

    monkeypatch.setattr(install_gate_api, "evaluate_install_command", _stub)

    r = test_client.post(f"{BASE}/evaluate", json=_REQUEST, headers={"X-Install-Key": "ic_install_key_stub"})

    assert r.status_code == 200
    assert captured[0]["owner_key"] == "owner-1"


def test_install_key_platform_mismatch_returns_403(test_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.install_keys.get_install_key_registry", lambda: _StubInstallKeyRegistry())

    r = test_client.post(f"{BASE}/evaluate", json={"platform": "hermes", "command": _CANONICAL_OPENCLAW}, headers={"X-Install-Key": "ic_install_key_stub"})

    assert r.status_code == 403


def test_extra_field_returns_422(test_client: TestClient) -> None:
    r = test_client.post(f"{BASE}/evaluate", json={**_REQUEST, "unexpected": True})

    assert r.status_code == 422


def test_empty_platform_returns_422(test_client: TestClient) -> None:
    r = test_client.post(f"{BASE}/evaluate", json={**_REQUEST, "platform": ""})

    assert r.status_code == 422


def test_empty_command_returns_422(test_client: TestClient) -> None:
    r = test_client.post(f"{BASE}/evaluate", json={**_REQUEST, "command": ""})

    assert r.status_code == 422


def test_over_length_command_returns_422(test_client: TestClient) -> None:
    r = test_client.post(f"{BASE}/evaluate", json={**_REQUEST, "command": "x" * 8193})

    assert r.status_code == 422
