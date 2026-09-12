from __future__ import annotations

import json
from types import SimpleNamespace

import cli.update as update_cli


def _make_key_record(**overrides):
    payload = {
        "active": True,
        "payment_status": "paid",
        "entitlements_status": "active",
        "issued_after_payment": True,
        "owner_key": "owner@example.com",
        "program": "openclaw",
        "key_id": "ik_openclaw_1",
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def test_update_preserves_verified_existing_install_key(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"install_key": "ic_install_openclaw_abc123"}), encoding="utf-8")

    def fake_authenticate(candidate):
        if candidate == "ic_install_openclaw_abc123":
            return _make_key_record()
        return None

    monkeypatch.setattr(update_cli, "get_install_key_registry", lambda: SimpleNamespace(authenticate_install_key=fake_authenticate))

    result = update_cli._resolve_install_key_for_update(
        config_path,
        program="openclaw",
        owner_key="owner@example.com",
    )

    assert result == "ic_install_openclaw_abc123"


def test_update_keeps_existing_key_when_new_value_is_blank_or_generic(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"install_key": "ic_install_openclaw_abc123"}), encoding="utf-8")

    def fake_authenticate(candidate):
        if candidate == "ic_install_openclaw_abc123":
            return _make_key_record()
        return None

    monkeypatch.setattr(update_cli, "get_install_key_registry", lambda: SimpleNamespace(authenticate_install_key=fake_authenticate))

    assert update_cli._resolve_install_key_for_update(config_path, program="openclaw", proposed_install_key="") == "ic_install_openclaw_abc123"
    assert update_cli._resolve_install_key_for_update(config_path, program="openclaw", proposed_install_key="sk_live_abc") == "ic_install_openclaw_abc123"


def test_update_rotates_only_when_existing_and_new_keys_are_verified(monkeypatch, tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"install_key": "ic_install_openclaw_old"}), encoding="utf-8")

    def fake_authenticate(candidate):
        if candidate == "ic_install_openclaw_old":
            return _make_key_record(key_id="ik_old", program="openclaw", owner_key="owner@example.com")
        if candidate == "ic_install_openclaw_new":
            return _make_key_record(key_id="ik_new", program="openclaw", owner_key="owner@example.com")
        return None

    monkeypatch.setattr(update_cli, "get_install_key_registry", lambda: SimpleNamespace(authenticate_install_key=fake_authenticate))

    result = update_cli._resolve_install_key_for_update(
        config_path,
        program="openclaw",
        owner_key="owner@example.com",
        proposed_install_key="ic_install_openclaw_new",
    )

    assert result == "ic_install_openclaw_new"
