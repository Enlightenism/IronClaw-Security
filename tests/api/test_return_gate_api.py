from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
import pytest

from app.api import return_gate as return_gate_api
from app.runtime.return_gate import BLOCKED_REPLACEMENT_TEXT, ReturnGateDecision

BASE = "/return-gate"
_REQUEST = {"platform": "claude_code", "content": "tool output", "payload": {"stdout": "ok"}}


@pytest.fixture
def gate_verdict(monkeypatch: pytest.MonkeyPatch) -> Any:
    captured: list[dict[str, Any]] = []

    def _set(verdict: str) -> list[dict[str, Any]]:
        blocked = verdict == "block"
        decision = ReturnGateDecision(
            verdict=verdict,
            sandbox_id="return-abc123",
            stage="inprocess" if blocked else "sandbox",
            reasons=["text_classifier"] if blocked else [],
            risk_score=100 if blocked else 0,
        )

        def _stub(**kwargs: Any) -> ReturnGateDecision:
            captured.append(kwargs)
            return decision

        monkeypatch.setattr(return_gate_api, "run_return_gate", _stub)
        return captured

    return _set


def test_scan_allow_response_shape(test_client: TestClient, gate_verdict: Any) -> None:
    gate_verdict("allow")

    r = test_client.post(f"{BASE}/scan", json=_REQUEST)

    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"verdict", "sandbox_id", "stage", "reasons", "risk_score", "audit_only"}
    assert body["verdict"] == "allow"
    assert body["audit_only"] is True
    assert "replacement" not in body


def test_scan_block_is_audit_only(test_client: TestClient, gate_verdict: Any) -> None:
    gate_verdict("block")

    r = test_client.post(f"{BASE}/scan", json=_REQUEST)

    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "block"
    assert body["stage"] == "inprocess"
    assert body["reasons"] == ["text_classifier"]
    assert "replacement" not in body


def test_transform_allow_returns_no_replacement(test_client: TestClient, gate_verdict: Any) -> None:
    gate_verdict("allow")

    r = test_client.post(f"{BASE}/transform", json=_REQUEST)

    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"verdict", "sandbox_id", "replacement", "reasons"}
    assert body["verdict"] == "allow"
    assert body["replacement"] is None


def test_transform_block_returns_replacement(test_client: TestClient, gate_verdict: Any) -> None:
    gate_verdict("block")

    r = test_client.post(f"{BASE}/transform", json=_REQUEST)

    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "block"
    assert body["replacement"] == BLOCKED_REPLACEMENT_TEXT


def test_routes_forward_fields_with_defaults(test_client: TestClient, gate_verdict: Any) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(f"{BASE}/scan", json={"platform": "goose", "agent_id": "ag-1"})

    assert r.status_code == 200
    assert captured[0]["platform"] == "goose"
    assert captured[0]["action_type"] == "tool_output"
    assert captured[0]["target"] == "return"
    assert captured[0]["agent_id"] == "ag-1"
    assert captured[0]["payload"] == {}


class _StubInstallKeyRegistry:
    def authenticate_install_key(self, candidate: str) -> SimpleNamespace:
        return SimpleNamespace(key_id="key-1", owner_key="owner-1", program="claude_code")


def test_install_key_scopes_owner_for_matching_platform(test_client: TestClient, gate_verdict: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = gate_verdict("allow")
    monkeypatch.setattr("app.core.install_keys.get_install_key_registry", lambda: _StubInstallKeyRegistry())

    r = test_client.post(f"{BASE}/scan", json=_REQUEST, headers={"X-Install-Key": "ic_install_key_stub"})

    assert r.status_code == 200
    assert captured[0]["owner_key"] == "owner-1"


def test_install_key_platform_mismatch_returns_403(test_client: TestClient, gate_verdict: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    gate_verdict("allow")
    monkeypatch.setattr("app.core.install_keys.get_install_key_registry", lambda: _StubInstallKeyRegistry())

    r = test_client.post(f"{BASE}/transform", json={"platform": "goose", "content": "tool output"}, headers={"X-Install-Key": "ic_install_key_stub"})

    assert r.status_code == 403


def test_extra_field_returns_422(test_client: TestClient, gate_verdict: Any) -> None:
    gate_verdict("allow")

    r = test_client.post(f"{BASE}/transform", json={**_REQUEST, "unexpected": True})

    assert r.status_code == 422


def test_empty_platform_returns_422(test_client: TestClient, gate_verdict: Any) -> None:
    gate_verdict("allow")

    r = test_client.post(f"{BASE}/scan", json={"platform": ""})

    assert r.status_code == 422


@pytest.mark.parametrize("tool_name", ["Bash", "Read", "Write", "WebFetch", "mcp__server__tool"])
def test_every_tool_is_scanned(test_client: TestClient, gate_verdict: Any, tool_name: str) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(f"{BASE}/scan", json={"platform": "claude_code", "payload": {"tool_name": tool_name}})

    assert r.status_code == 200
    assert captured[0]["payload"]["tool_name"] == tool_name


def test_url_and_command_fields_merge_into_payload(test_client: TestClient, gate_verdict: Any) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(
        f"{BASE}/scan",
        json={"platform": "cursor", "payload": {"tool_name": "Shell"}, "url": "https://example.com/a", "command": "curl https://example.com/a"},
    )

    assert r.status_code == 200
    assert captured[0]["payload"] == {"tool_name": "Shell", "url": "https://example.com/a", "command": "curl https://example.com/a"}


def test_top_level_url_overrides_nested_payload_url(test_client: TestClient, gate_verdict: Any) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(f"{BASE}/scan", json={"platform": "claude_code", "payload": {"url": "https://old.example"}, "url": "https://new.example"})

    assert r.status_code == 200
    assert captured[0]["payload"]["url"] == "https://new.example"


def test_file_path_field_merges_into_payload(test_client: TestClient, gate_verdict: Any) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(
        f"{BASE}/scan",
        json={"platform": "claude_code", "payload": {"tool_name": "Read"}, "file_path": "notes/readme.md"},
    )

    assert r.status_code == 200
    assert captured[0]["payload"] == {"tool_name": "Read", "file_path": "notes/readme.md"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("url", "u" * (return_gate_api.RETURN_URL_MAX_CHARS + 1), id="url-too-long"),
        pytest.param("command", "c" * (return_gate_api.RETURN_COMMAND_MAX_CHARS + 1), id="command-too-long"),
        pytest.param("file_path", "f" * (return_gate_api.RETURN_FILE_PATH_MAX_CHARS + 1), id="file-path-too-long"),
    ],
)
def test_oversized_string_fields_return_422(test_client: TestClient, gate_verdict: Any, field: str, value: str) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(f"{BASE}/scan", json={"platform": "claude_code", field: value})

    assert r.status_code == 422
    assert captured == []


def test_oversized_payload_returns_400(test_client: TestClient, gate_verdict: Any) -> None:
    captured = gate_verdict("allow")

    r = test_client.post(
        f"{BASE}/scan",
        json={"platform": "claude_code", "payload": {"blob": "x" * return_gate_api.RETURN_PAYLOAD_MAX_BYTES}},
    )

    assert r.status_code == 400
    assert captured == []
