from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import app.api.health as health_module
from app.api.health import HealthStatus


class _Broker:
    def __init__(self, payload: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self._payload = payload
        self._error = error

    def health(self) -> dict[str, Any]:
        if self._error is not None:
            raise self._error
        assert self._payload is not None
        return self._payload


def test_return_gate_component_ok_when_broker_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"reachable": True, "reason": None, "scanner_image": "ready"}
    monkeypatch.setattr(health_module, "SandboxBrokerClient", lambda: _Broker(payload))

    component = health_module._build_return_gate_component()

    assert component.name == "return_gate"
    assert component.status == HealthStatus.ok


def test_return_gate_component_degraded_when_broker_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health_module, "SandboxBrokerClient", lambda: _Broker({"reachable": False, "reason": "broker_unreachable"}))

    component = health_module._build_return_gate_component()

    assert component.name == "return_gate"
    assert component.status == HealthStatus.degraded
    assert component.details["reason"] == "broker_unreachable"


def test_return_gate_component_degraded_when_scanner_image_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"reachable": True, "reason": None, "scanner_image": "missing"}
    monkeypatch.setattr(health_module, "SandboxBrokerClient", lambda: _Broker(payload))

    component = health_module._build_return_gate_component()

    assert component.status == HealthStatus.degraded
    assert component.details["scanner_image"] == "missing"
    assert component.details["reason"] == "scanner_image_not_ready"


def test_return_gate_component_degraded_when_broker_omits_scanner_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health_module, "SandboxBrokerClient", lambda: _Broker({"reachable": True, "reason": None}))

    component = health_module._build_return_gate_component()

    assert component.status == HealthStatus.degraded
    assert component.details["scanner_image"] == "unknown"
    assert component.details["reason"] == "scanner_image_not_ready"


def test_return_gate_component_errors_when_health_check_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health_module, "SandboxBrokerClient", lambda: _Broker(error=RuntimeError("boom")))

    component = health_module._build_return_gate_component()

    assert component.name == "return_gate"
    assert component.status == HealthStatus.error


def test_install_gate_component_reports_scan_and_allow_policy() -> None:
    component = health_module._build_install_gate_component()

    assert component.name == "install_gate"
    assert component.status == HealthStatus.ok
    assert component.details["policy"] == "scan-and-allow"
    assert component.details["third_party_scan"] == "sandbox_broker"


def test_read_compact_health_appends_gate_components_and_degrades_without_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(health_module, "_build_api_component", lambda: health_module.ComponentHealth(name="api", status=HealthStatus.ok, details={}))
    monkeypatch.setattr(
        health_module,
        "_build_secure_runtime_component",
        lambda: health_module.ComponentHealth(name="secure_runtime_pipeline", status=HealthStatus.ok, details={}),
    )
    monkeypatch.setattr(health_module, "SandboxBrokerClient", lambda: _Broker({"reachable": False, "reason": "broker_unconfigured"}))

    snapshot = health_module.read_compact_health()

    names = [component.name for component in snapshot.components]
    assert names[-3:] == ["return_gate", "install_gate", "prompt_guard"]
    assert snapshot.metadata["component_count"] == 5
    assert snapshot.status == HealthStatus.degraded


def _set_guard(monkeypatch: pytest.MonkeyPatch, *, enabled: bool, model_dir: Path) -> None:
    monkeypatch.setattr(
        health_module,
        "get_settings",
        lambda: SimpleNamespace(guard_enabled=enabled, guard_model_path=str(model_dir)),
    )
    monkeypatch.setattr(health_module, "resolve_prompt_guard_path", lambda _path: model_dir)


def test_prompt_guard_component_warns_when_disabled(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_guard(monkeypatch, enabled=False, model_dir=tmp_path)

    component = health_module._build_prompt_guard_component()

    assert component.status == HealthStatus.warn
    assert component.details["reason"] == "prompt_guard_disabled"


def test_prompt_guard_component_degraded_when_enabled_without_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_guard(monkeypatch, enabled=True, model_dir=tmp_path)

    component = health_module._build_prompt_guard_component()

    assert component.status == HealthStatus.degraded
    assert component.details["reason"] == "prompt_guard_model_missing"


def test_prompt_guard_component_ok_when_enabled_with_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "model.safetensors").write_bytes(b"")
    _set_guard(monkeypatch, enabled=True, model_dir=tmp_path)

    component = health_module._build_prompt_guard_component()

    assert component.status == HealthStatus.ok
    assert component.details["model_files_present"] is True
