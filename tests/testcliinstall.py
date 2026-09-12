from __future__ import annotations

import importlib
import json
from pathlib import Path
import tomllib
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
        "Unable to import installer module. Expected one of: " + ", ".join(MODULE_CANDIDATES),
    ) from last_error


@pytest.fixture
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


def test_example_skill_config_uses_canonical_multi_platform_targets(install_module: Any) -> None:
    config_path = Path(__file__).resolve().parents[1] / "config" / "ironclaw_skill.example.toml"
    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))

    expected = [
        "claude_code",
        "openclaw",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "hermes",
    ]

    assert payload["ironclaw"]["provider_targets"] == expected
    assert set(payload["ironclaw"]["provider_targets"]) == set(install_module.DEFAULT_PROVIDER_TARGETS)


def test_build_install_config_defaults(install_module: Any, tmp_path: Path) -> None:
    parser = install_module.build_parser()
    args = parser.parse_args(
        [
            "--project-root",
            str(tmp_path),
            "--config-dir",
            str(tmp_path / ".ironclaw-user"),
        ],
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
    assert list(config.provider_targets) == [
        "openclaw",
        "claude_code",
        "cursor",
        "goose",
        "gemini_cli",
        "copilot",
        "hermes",
    ]


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
        ],
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
            "--provider-target",
            "copilot",
        ],
    )

    config = install_module.build_install_config(args)
    assert config.provider_targets == ("claude_code", "openclaw", "copilot")

    bad_parser = install_module.build_parser()
    bad_args = bad_parser.parse_args(
        [
            "--project-root",
            str(tmp_path),
            "--config-dir",
            str(tmp_path / ".ironclaw-user"),
            "--provider-target",
            "security-guardian",
        ],
    )
    with pytest.raises(install_module.IronClawInstallerError, match="Unsupported provider target"):
        install_module.build_install_config(bad_args)


def test_install_key_injection_uses_canonical_runtime_names_and_commands(
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
            "--install-key",
            "claude_code=ic_install_claude_code_abc123",
            "--install-key",
            "openclaw=ic_install_openclaw_def456",
            "--install-key",
            "hermes=ic_install_hermes_ghi789",
        ],
    )

    config = install_module.build_install_config(args)
    assert config.install_keys == {
        "claude_code": "ic_install_claude_code_abc123",
        "openclaw": "ic_install_openclaw_def456",
        "hermes": "ic_install_hermes_ghi789",
    }
    assert config.provider_targets == install_module.DEFAULT_PROVIDER_TARGETS
    assert install_module.build_install_key_commands(config.install_keys)["claude_code"] == ("gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_abc123")
    assert install_module.build_install_key_commands(config.install_keys)["hermes"] == ("hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_ghi789")

    with pytest.raises(install_module.IronClawInstallerError, match="install key"):
        install_module._validate_install_key_for_runtime("openclaw", "sk_live_abc123")

    with pytest.raises(install_module.IronClawInstallerError, match="install key"):
        install_module._validate_install_key_for_runtime("openclaw", "")


@pytest.mark.parametrize(
    ("runtime_program", "install_key", "expected_command"),
    [
        ("openclaw", "ic_install_openclaw_abc123", "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user --key ic_install_openclaw_abc123"),
        ("claude_code", "ic_install_claude_code_abc123", "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_abc123"),
        ("cursor", "ic_install_cursor_abc123", "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key ic_install_cursor_abc123"),
        ("goose", "ic_install_goose_abc123", "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key ic_install_goose_abc123"),
        ("gemini_cli", "ic_install_gemini_cli_abc123", "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user --key ic_install_gemini_cli_abc123"),
        ("copilot", "ic_install_copilot_abc123", "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key ic_install_copilot_abc123"),
        ("hermes", "ic_install_hermes_abc123", "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_abc123"),
    ],
)
def test_build_install_key_commands_emit_canonical_commands_for_every_supported_runtime(
    install_module: Any,
    runtime_program: str,
    install_key: str,
    expected_command: str,
) -> None:
    commands = install_module.build_install_key_commands({runtime_program: install_key})

    assert commands[runtime_program] == expected_command
    assert install_key.startswith(install_module.InstallKeyFormatRegistry.get_spec(runtime_program).prefix)
    assert expected_command.count(install_key) == 1
    assert "placeholder" not in expected_command.lower()
    assert "fake" not in expected_command.lower()
    assert "..." not in expected_command
    assert "***" not in expected_command


@pytest.mark.parametrize(
    ("runtime_program", "install_key"),
    [
        ("openclaw", ""),
        ("openclaw", "placeholder"),
        ("openclaw", "********"),
        ("openclaw", "ic_install_openclaw_***"),
        ("openclaw", "ic_install_openclaw_placeholder"),
        ("openclaw", "ic_install_openclaw_stale_key"),
        ("claude_code", "sk_live_abc123"),
        ("cursor", "ghp_abc123"),
        ("goose", "token_abc123"),
        ("gemini_cli", "ic_org_12345"),
        ("copilot", "ic_install_copilot_...abcd"),
        ("hermes", "ic_install_hermes_***"),
    ],
)
def test_install_key_validation_rejects_blank_placeholder_masked_and_fake_values(
    install_module: Any,
    runtime_program: str,
    install_key: str,
) -> None:
    with pytest.raises(install_module.IronClawInstallerError, match="valid paid install key|install key"):
        install_module._validate_install_key_for_runtime(runtime_program, install_key)

    with pytest.raises(install_module.IronClawInstallerError, match="valid paid install key|install key"):
        install_module.build_install_key_commands({runtime_program: install_key})

    with pytest.raises(install_module.IronClawInstallerError, match="valid paid install key|install key"):
        install_module._build_platform_install_command(runtime_program, install_key)


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
            "--provider-target",
            "hermes",
        ],
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
    assert runtime_payload["schema_version"] == 1
    assert runtime_payload["product"] == "IronClaw-Security"
    assert runtime_payload["install_mode"] == "local-bootstrap"
    assert runtime_payload["skill_mode"] is True
    assert runtime_payload["base_url"] == install_module.DEFAULT_BASE_URL
    assert runtime_payload["provider_targets"] == ["claude_code", "openclaw", "hermes"]
    assert runtime_payload["features"]["shared_skill_package"] is True
    assert runtime_payload["features"]["claude_integration"] is True
    assert runtime_payload["features"]["openclaw_integration"] is True
    assert runtime_payload["features"]["hermes_integration"] is True
    assert runtime_payload["install_keys"] == {}

    skill_payload = json.loads(result.skill_config_file.read_text(encoding="utf-8"))
    assert skill_payload["enabled"] is True
    assert skill_payload["provider_targets"] == ["claude_code", "openclaw", "hermes"]
    assert skill_payload["default_policy_mode"] == "review"

    env_contents = result.env_file.read_text(encoding="utf-8")
    assert "IRONCLAW_BASE_URL=http://127.0.0.1:8000" in env_contents
    assert "IRONCLAW_PROVIDER_TARGETS=claude_code,openclaw,hermes" in env_contents
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
        ],
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
        ],
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
        ],
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "failed" in captured.err.lower()
