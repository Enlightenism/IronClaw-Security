from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest

MODULE_CANDIDATES = (
    "ironclaw_installer",
    "cli.install",
    "scripts.install",
)


def _import_install_module() -> Any:
    last_error: Exception | None = None
    for module_name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            last_error = exc
    raise AssertionError(
        "Unable to import installer module. Expected one of: "
        + ", ".join(MODULE_CANDIDATES)
    ) from last_error


@pytest.fixture()
def install_module() -> Any:
    return _import_install_module()


def test_installer_module_exports_expected_symbols(install_module: Any) -> None:
    expected = (
        "InstallConfig",
        "InstallResult",
        "IronClawInstallerError",
        "build_parser",
        "build_install_config",
        "run_install",
        "main",
    )
    missing = [name for name in expected if getattr(install_module, name, None) is None]
    assert not missing, f"Missing installer symbols: {', '.join(missing)}"


def test_build_install_config_defaults(install_module: Any, tmp_path: Path) -> None:
    parser = install_module.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(tmp_path),
            "--config-dir",
            str(tmp_path / ".ironclaw-user"),
        ]
    )

    config = install_module.build_install_config(args)

    assert config.project_root == tmp_path.resolve()
    assert config.config_dir == (tmp_path / ".ironclaw-user").resolve()
    assert config.config_file == config.config_dir / install_module.DEFAULT_CONFIG_FILENAME
    assert config.env_file == config.project_root / install_module.DEFAULT_ENV_FILENAME
    assert config.base_url == install_module.DEFAULT_BASE_URL
    assert config.backup_target == install_module.DEFAULT_BACKUP_TARGET
    assert config.restore_target == install_module.DEFAULT_RESTORE_TARGET
    assert config.retention_days == install_module.DEFAULT_RETENTION_DAYS
    assert config.install_vscode_settings is True
    assert config.install_skill_config is True
    assert config.write_env_file is True
    assert config.overwrite is False
    assert config.provider_targets == install_module.DEFAULT_PROVIDER_TARGETS


def test_build_install_config_rejects_invalid_retention_days(
    install_module: Any,
    tmp_path: Path,
) -> None:
    parser = install_module.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(tmp_path),
            "--config-dir",
            str(tmp_path / ".ironclaw-user"),
            "--retention-days",
            "0",
        ]
    )

    with pytest.raises(install_module.IronClawInstallerError, match="retention-days"):
        install_module.build_install_config(args)


def test_build_install_config_normalizes_provider_targets(
    install_module: Any,
    tmp_path: Path,
) -> None:
    parser = install_module.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(tmp_path),
            "--config-dir",
            str(tmp_path / ".ironclaw-user"),
            "--provider-target",
            "claude",
            "--provider-target",
            "openclaw",
            "--provider-target",
            "claude",
        ]
    )

    config = install_module.build_install_config(args)
    assert config.provider_targets == ("claude", "openclaw")


def test_run_install_writes_expected_files(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / "pyproject.toml").write_text(
        "[build-system]\nrequires = []\nbuild-backend = 'setuptools.build_meta'\n",
        encoding="utf-8",
    )

    config_dir = tmp_path / "user-config"

    parser = install_module.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(project_root),
            "--config-dir",
            str(config_dir),
            "--provider-target",
            "claude",
            "--provider-target",
            "openclaw",
        ]
    )
    config = install_module.build_install_config(args)

    monkeypatch.setattr(install_module, "_create_virtualenv", lambda project_root: None)
    monkeypatch.setattr(install_module, "_install_project_editable", lambda project_root: None)

    result = install_module.run_install(config)

    assert result.ok is True
    assert result.config_file.exists()
    assert result.env_file is not None
    assert result.env_file.exists()
    assert result.vscode_settings_file is not None
    assert result.vscode_settings_file.exists()
    assert result.skill_config_file is not None
    assert result.skill_config_file.exists()

    runtime_payload = json.loads(result.config_file.read_text(encoding="utf-8"))
    assert runtime_payload["product"] == "IronClaw-Security"
    assert runtime_payload["base_url"] == install_module.DEFAULT_BASE_URL
    assert runtime_payload["provider_targets"] == ["claude", "openclaw"]

    skill_payload = json.loads(result.skill_config_file.read_text(encoding="utf-8"))
    assert skill_payload["enabled"] is True
    assert skill_payload["provider_targets"] == ["claude", "openclaw"]
    assert skill_payload["default_policy_mode"] == "review"

    env_contents = result.env_file.read_text(encoding="utf-8")
    assert "IRONCLAW_BASE_URL=http://127.0.0.1:8000" in env_contents
    assert "IRONCLAW_PROVIDER_TARGETS=claude,openclaw" in env_contents
    assert "API_SECRET=" in env_contents
    assert "JWT_SECRET=" in env_contents
    assert "SECRET_KEY=" in env_contents

    vscode_payload = json.loads(result.vscode_settings_file.read_text(encoding="utf-8"))
    assert vscode_payload["python.testing.pytestEnabled"] is True


def test_run_install_skips_existing_files_without_overwrite(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / "pyproject.toml").write_text(
        "[build-system]\nrequires = []\nbuild-backend = 'setuptools.build_meta'\n",
        encoding="utf-8",
    )

    config_dir = tmp_path / "user-config"
    config_dir.mkdir(parents=True, exist_ok=True)

    config_file = config_dir / install_module.DEFAULT_CONFIG_FILENAME
    env_file = project_root / install_module.DEFAULT_ENV_FILENAME
    skill_file = config_dir / install_module.DEFAULT_SKILL_CONFIG_FILENAME
    vscode_file = project_root / ".vscode" / "settings.json"
    vscode_file.parent.mkdir(parents=True, exist_ok=True)

    config_file.write_text(json.dumps({"preexisting": True}) + "\n", encoding="utf-8")
    env_file.write_text("PREEXISTING_ENV=true\n", encoding="utf-8")
    skill_file.write_text(json.dumps({"enabled": False}) + "\n", encoding="utf-8")
    vscode_file.write_text(json.dumps({"editor.formatOnSave": False}) + "\n", encoding="utf-8")

    parser = install_module.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(project_root),
            "--config-dir",
            str(config_dir),
        ]
    )
    config = install_module.build_install_config(args)

    monkeypatch.setattr(install_module, "_create_virtualenv", lambda project_root: None)
    monkeypatch.setattr(install_module, "_install_project_editable", lambda project_root: None)

    result = install_module.run_install(config)

    skipped = set(result.skipped_paths)
    assert str(config_file) in skipped
    assert str(env_file) in skipped
    assert str(skill_file) in skipped
    assert str(vscode_file) in skipped

    assert json.loads(config_file.read_text(encoding="utf-8")) == {"preexisting": True}
    assert env_file.read_text(encoding="utf-8") == "PREEXISTING_ENV=true\n"
    assert json.loads(skill_file.read_text(encoding="utf-8")) == {"enabled": False}
    assert json.loads(vscode_file.read_text(encoding="utf-8")) == {"editor.formatOnSave": False}


def test_main_returns_zero_for_json_install(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / "pyproject.toml").write_text(
        "[build-system]\nrequires = []\nbuild-backend = 'setuptools.build_meta'\n",
        encoding="utf-8",
    )
    config_dir = tmp_path / "user-config"

    monkeypatch.setattr(install_module, "_create_virtualenv", lambda project_root: None)
    monkeypatch.setattr(install_module, "_install_project_editable", lambda project_root: None)

    exit_code = install_module.main(
        [
            "--project-root",
            str(project_root),
            "--config-dir",
            str(config_dir),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["config_file"] == str(config_dir / install_module.DEFAULT_CONFIG_FILENAME)


def test_main_returns_one_when_project_root_is_invalid(
    install_module: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_root = tmp_path / "missing-project"
    config_dir = tmp_path / "user-config"

    exit_code = install_module.main(
        [
            "--project-root",
            str(project_root),
            "--config-dir",
            str(config_dir),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "failed" in captured.err.lower()