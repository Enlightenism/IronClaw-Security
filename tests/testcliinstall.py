from __future__ import annotations

import importlib
import io
import json
from pathlib import Path
import sys
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
        "BootstrapResult",
        "InstallConfig",
        "InstallResult",
        "IronClawInstallerError",
        "build_bootstrap_parser",
        "build_parser",
        "build_install_config",
        "run_bootstrap",
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
    assert "groq_api_key" not in payload["providers"]


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


def test_install_claims_use_canonical_runtime_names_and_commands(
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
            "--install-claim",
            "claude_code=ic_claim_0123456789abcdefghij",
            "--install-claim",
            "openclaw=ic_claim_abcdefghij0123456789",
            "--install-claim",
            "hermes=ic_claim_ABCDEFGHIJ0123456789",
        ],
    )

    config = install_module.build_install_config(args)
    assert config.install_claims == {
        "claude_code": "ic_claim_0123456789abcdefghij",
        "openclaw": "ic_claim_abcdefghij0123456789",
        "hermes": "ic_claim_ABCDEFGHIJ0123456789",
    }
    assert config.provider_targets == install_module.DEFAULT_PROVIDER_TARGETS
    commands = install_module.build_install_claim_commands(config.install_claims)
    assert commands["claude_code"] == (
        "python -m pip install --no-deps --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git\n"
        "python -m ironclaw_installer bootstrap --program claude_code --claim-token ic_claim_0123456789abcdefghij"
    )
    assert commands["hermes"] == (
        "python -m pip install --no-deps --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git\n"
        "python -m ironclaw_installer bootstrap --program hermes --claim-token ic_claim_ABCDEFGHIJ0123456789"
    )
    assert set(config.to_dict()["install_claims"].values()) == {"[REDACTED]"}

    with pytest.raises(install_module.IronClawInstallerError, match="install key"):
        install_module._validate_install_key_for_runtime("openclaw", "sk_live_abc123")

    with pytest.raises(install_module.IronClawInstallerError, match="install key"):
        install_module._validate_install_key_for_runtime("openclaw", "")


@pytest.mark.parametrize(
    ("runtime_program", "claim_token"),
    [
        (program, "ic_claim_0123456789abcdefghij")
        for program in (
            "openclaw",
            "claude_code",
            "cursor",
            "goose",
            "gemini_cli",
            "copilot",
            "hermes",
        )
    ],
)
def test_build_install_claim_commands_use_canonical_templates_for_every_runtime(
    install_module: Any,
    runtime_program: str,
    claim_token: str,
) -> None:
    commands = install_module.build_install_claim_commands({runtime_program: claim_token})

    expected_command = install_module.InstallKeyFormatRegistry.get_spec(runtime_program).format_command(claim_token)
    assert commands[runtime_program] == expected_command
    assert commands[runtime_program].count(claim_token) == 1
    assert "placeholder" not in commands[runtime_program].lower()
    assert "fake" not in commands[runtime_program].lower()
    assert "..." not in commands[runtime_program]
    assert "***" not in commands[runtime_program]


@pytest.mark.parametrize(
    ("runtime_program", "expected_command"),
    [
        (
            "openclaw",
            ["gh", "skill", "install", "Enlightenism/IronClaw-Security", "skills/ironclaw-security", "--agent", "openclaw", "--scope", "user"],
        ),
        (
            "claude_code",
            ["gh", "skill", "install", "Enlightenism/IronClaw-Security", "skills/ironclaw-security", "--agent", "claude-code", "--scope", "user"],
        ),
        (
            "cursor",
            ["gh", "skill", "install", "Enlightenism/IronClaw-Security", "skills/ironclaw-security", "--agent", "cursor", "--scope", "user"],
        ),
        (
            "goose",
            ["gh", "skill", "install", "Enlightenism/IronClaw-Security", "skills/ironclaw-security", "--agent", "goose", "--scope", "user"],
        ),
        (
            "gemini_cli",
            ["gh", "skill", "install", "Enlightenism/IronClaw-Security", "skills/ironclaw-security", "--agent", "gemini-cli", "--scope", "user"],
        ),
        (
            "copilot",
            ["gh", "skill", "install", "Enlightenism/IronClaw-Security", "skills/ironclaw-security", "--agent", "github-copilot", "--scope", "user"],
        ),
        (
            "hermes",
            ["hermes", "skills", "install", "https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md", "--name", "ironclaw-security"],
        ),
    ],
)
def test_runtime_skill_install_command_uses_canonical_host_metadata(
    install_module: Any,
    runtime_program: str,
    expected_command: list[str],
) -> None:
    assert install_module._runtime_skill_install_command(runtime_program) == expected_command


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
def test_install_claim_validation_rejects_raw_keys_and_placeholder_values(
    install_module: Any,
    runtime_program: str,
    install_key: str,
) -> None:
    with pytest.raises(install_module.IronClawInstallerError, match="one-time install claim"):
        install_module._validate_install_claim_for_runtime(runtime_program, install_key)

    with pytest.raises(install_module.IronClawInstallerError, match="one-time install claim"):
        install_module.build_install_claim_commands({runtime_program: install_key})

    with pytest.raises(install_module.IronClawInstallerError, match="one-time install claim"):
        install_module._build_platform_install_claim_command(runtime_program, install_key)


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
    assert runtime_payload["runtime_commands"] == {}

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


def test_run_install_redeems_claim_and_keeps_key_out_of_results(
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
    claim_token = "ic_claim_0123456789abcdefghij"
    install_key = "ic_install_claude_code_abc123"
    requests: list[Any] = []

    def fake_open_claim_request(request: Any, *, timeout: float) -> io.BytesIO:
        requests.append(request)
        assert timeout == install_module.DEFAULT_TIMEOUT_SECONDS
        return io.BytesIO(
            json.dumps(
                {
                    "key_id": "ik_claude_123",
                    "program": "claude_code",
                    "install_key": install_key,
                },
            ).encode("utf-8"),
        )

    monkeypatch.setattr(install_module, "_open_install_claim_request", fake_open_claim_request)
    monkeypatch.setattr(install_module, "_create_virtualenv", lambda project_root: None)
    monkeypatch.setattr(install_module, "_install_project_editable", lambda project_root: None)

    args = install_module.build_parser().parse_args(
        [
            "--project-root",
            str(project_root),
            "--config-dir",
            str(tmp_path / "user-config"),
            "--provider-target",
            "claude_code",
            "--install-claim",
            f"claude_code={claim_token}",
        ],
    )
    config = install_module.build_install_config(args)
    result = install_module.run_install(config)

    request = requests[0]
    assert request.get_method() == "POST"
    assert request.full_url.endswith("/integrations/install-claims/redeem")
    assert json.loads(request.data) == {"claim_token": claim_token}

    runtime_payload = json.loads(result.config_file.read_text(encoding="utf-8"))
    assert runtime_payload["install_keys"] == {"claude_code": install_key}
    assert runtime_payload["runtime_commands"] == {
        "claude_code": install_module.InstallKeyFormatRegistry.get_spec("claude_code").generic_command,
    }
    assert claim_token not in result.config_file.read_text(encoding="utf-8")
    assert install_key not in runtime_payload["runtime_commands"]["claude_code"]
    assert claim_token not in json.dumps(config.to_dict())
    assert install_key not in json.dumps(result.to_dict())
    assert claim_token not in json.dumps(result.to_dict())


def test_run_bootstrap_redeems_once_persists_privately_and_installs_the_shared_skill(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim_token = "ic_claim_0123456789abcdefghij"
    install_key = "ic_install_claude_code_abc123"
    requests: list[Any] = []
    commands: list[list[str]] = []
    protected_paths: list[Path] = []

    def fake_open_claim_request(request: Any, *, timeout: float) -> io.BytesIO:
        requests.append(request)
        assert timeout == install_module.DEFAULT_TIMEOUT_SECONDS
        return io.BytesIO(
            json.dumps(
                {
                    "key_id": "ik_claude_bootstrap_001",
                    "program": "claude_code",
                    "install_key": install_key,
                },
            ).encode("utf-8"),
        )

    def fake_subprocess_run(command: list[str], **kwargs: Any) -> None:
        commands.append(command)
        assert kwargs == {"check": True, "timeout": install_module._SUBPROCESS_TIMEOUT}

    monkeypatch.setattr(install_module, "_open_install_claim_request", fake_open_claim_request)
    monkeypatch.setattr(install_module, "_restrict_private_file_permissions", protected_paths.append)
    monkeypatch.setattr(install_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(install_module.subprocess, "run", fake_subprocess_run)

    config_dir = tmp_path / "user-config"
    result = install_module.run_bootstrap(
        program="claude_code",
        claim_token=claim_token,
        config_dir=config_dir,
    )

    request = requests[0]
    assert request.get_method() == "POST"
    assert request.full_url == ("https://ironclaw-security.onrender.com/integrations/install-claims/redeem")
    assert json.loads(request.data) == {"claim_token": claim_token}
    assert commands == [
        [
            "gh",
            "skill",
            "install",
            "Enlightenism/IronClaw-Security",
            "skills/ironclaw-security",
            "--agent",
            "claude-code",
            "--scope",
            "user",
        ],
    ]
    assert protected_paths == [config_dir / install_module.DEFAULT_CONFIG_FILENAME]

    saved_config = json.loads(result.config_file.read_text(encoding="utf-8"))
    assert saved_config["install_keys"] == {"claude_code": install_key}
    assert saved_config["provider_targets"] == ["claude_code"]
    assert saved_config["installed_skills"] == {"claude_code": "ironclaw-security"}
    assert saved_config["features"]["claude_integration"] is True
    assert saved_config["runtime_commands"]["claude_code"] == (install_module.InstallKeyFormatRegistry.get_spec("claude_code").generic_command)
    assert claim_token not in result.config_file.read_text(encoding="utf-8")
    assert install_key not in json.dumps(result.to_dict())
    assert claim_token not in json.dumps(result.to_dict())
    assert install_key not in repr(result)


def test_run_bootstrap_installs_fail_closed_openclaw_plugin(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claim_token = "ic_claim_0123456789abcdefghij"
    install_key = "ic_install_openclaw_abc123"
    requests: list[Any] = []
    commands: list[list[str]] = []

    def fake_open_claim_request(request: Any, *, timeout: float) -> io.BytesIO:
        requests.append(request)
        assert timeout == install_module.DEFAULT_TIMEOUT_SECONDS
        return io.BytesIO(
            json.dumps(
                {
                    "key_id": "ik_openclaw_bootstrap_001",
                    "program": "openclaw",
                    "install_key": install_key,
                },
            ).encode("utf-8"),
        )

    def fake_subprocess_run(command: list[str], **kwargs: Any) -> None:
        commands.append(command)
        assert kwargs == {"check": True, "timeout": install_module._SUBPROCESS_TIMEOUT}

    monkeypatch.setattr(install_module, "_open_install_claim_request", fake_open_claim_request)
    monkeypatch.setattr(install_module, "_restrict_private_file_permissions", lambda _: None)
    monkeypatch.setattr(install_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(install_module.subprocess, "run", fake_subprocess_run)

    config_dir = tmp_path / "user-config"
    result = install_module.run_bootstrap(
        program="openclaw",
        claim_token=claim_token,
        config_dir=config_dir,
    )

    plugin_dir = config_dir / "openclaw-plugin"
    config_file = (config_dir / install_module.DEFAULT_CONFIG_FILENAME).resolve()
    assert requests[0].full_url == "https://ironclaw-security.onrender.com/integrations/install-claims/redeem"
    assert json.loads(requests[0].data) == {"claim_token": claim_token}
    assert commands == [
        [
            "gh",
            "skill",
            "install",
            "Enlightenism/IronClaw-Security",
            "skills/ironclaw-security",
            "--agent",
            "openclaw",
            "--scope",
            "user",
        ],
        ["openclaw", "plugins", "install", "--link", str(plugin_dir), "--force"],
        [
            "openclaw",
            "config",
            "set",
            "plugins.entries.ironclaw-security.config.configFile",
            str(config_file),
        ],
        [
            "openclaw",
            "config",
            "set",
            "plugins.entries.ironclaw-security.config.pythonPath",
            sys.executable,
        ],
        ["openclaw", "plugins", "enable", "ironclaw-security"],
    ]

    saved_config = json.loads(result.config_file.read_text(encoding="utf-8"))
    assert saved_config["install_keys"] == {"openclaw": install_key}
    for filename in ("package.json", "openclaw.plugin.json", "index.js", "policy.js"):
        plugin_file = plugin_dir / filename
        assert plugin_file.is_file()
        plugin_contents = plugin_file.read_text(encoding="utf-8")
        assert claim_token not in plugin_contents
        assert install_key not in plugin_contents
    assert install_key not in json.dumps(commands)
    assert claim_token not in json.dumps(commands)


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


def test_run_bootstrap_missing_installer_does_not_redeem_claim(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[Any] = []
    monkeypatch.setattr(install_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(install_module, "_open_install_claim_request", lambda request, *, timeout: requests.append(request))

    with pytest.raises(install_module.IronClawInstallerError, match="'gh' was not found"):
        install_module.run_bootstrap(
            program="claude_code",
            claim_token="ic_claim_0123456789abcdefghij",
            config_dir=tmp_path / "user-config",
        )

    assert requests == []
    assert not (tmp_path / "user-config" / install_module.DEFAULT_CONFIG_FILENAME).exists()


def test_run_bootstrap_runs_on_key_saved_before_skill_install_failure(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_key = "ic_install_claude_code_abc123"
    events: list[str] = []

    def fake_open_claim_request(request: Any, *, timeout: float) -> io.BytesIO:
        return io.BytesIO(
            json.dumps({"key_id": "ik_claude_bootstrap_002", "program": "claude_code", "install_key": install_key}).encode("utf-8"),
        )

    def fake_subprocess_run(command: list[str], **kwargs: Any) -> None:
        events.append("skill_install")
        raise install_module.subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(install_module.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(install_module, "_open_install_claim_request", fake_open_claim_request)
    monkeypatch.setattr(install_module, "_restrict_private_file_permissions", lambda _: None)
    monkeypatch.setattr(install_module.subprocess, "run", fake_subprocess_run)

    config_dir = tmp_path / "user-config"
    with pytest.raises(install_module.IronClawInstallerError, match="Shared skill installation failed"):
        install_module.run_bootstrap(
            program="claude_code",
            claim_token="ic_claim_0123456789abcdefghij",
            config_dir=config_dir,
            on_key_saved=lambda: events.append("key_saved"),
        )

    assert events == ["key_saved", "skill_install"]
    saved_config = json.loads((config_dir / install_module.DEFAULT_CONFIG_FILENAME).read_text(encoding="utf-8"))
    assert saved_config["install_keys"] == {"claude_code": install_key}


def test_report_runtime_hook_goose_writes_pre_tool_block_plugin(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    plan = install_module._runtime_hook_plan("goose", True)
    exit_code = install_module._report_runtime_hook("goose", True, plan)

    plugin_root = tmp_path / ".agents" / "plugins" / "ironclaw-security"
    hooks = json.loads((plugin_root / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    assert exit_code == 0
    assert (plugin_root / "plugin.json").is_file()
    assert hooks["hooks"]["PreToolUse"][0]["hooks"][0]["on_failure"] == "block"
    assert "guidance-only" not in capsys.readouterr().out


def test_report_runtime_hook_hermes_copies_plugin_and_enables_it(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_subprocess_run(command: list[str], **kwargs: Any) -> None:
        commands.append(command)
        assert kwargs == {"check": True, "timeout": install_module._SUBPROCESS_TIMEOUT}

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(install_module.subprocess, "run", fake_subprocess_run)

    plan = install_module._runtime_hook_plan("hermes", True)
    exit_code = install_module._report_runtime_hook("hermes", True, plan)

    plugin_dir = tmp_path / ".hermes" / "plugins" / install_module.HERMES_PLUGIN_ID
    assert plan == []
    assert exit_code == 0
    assert (plugin_dir / "__init__.py").is_file()
    assert (plugin_dir / "plugin.yaml").is_file()
    assert commands == [["hermes", "plugins", "enable", "ironclaw-security"]]


def test_report_runtime_hook_hermes_fails_when_cli_is_missing(
    install_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake_subprocess_run(command: list[str], **kwargs: Any) -> None:
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setattr(install_module.subprocess, "run", fake_subprocess_run)

    exit_code = install_module._report_runtime_hook("hermes", True, [])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "hermes plugins enable ironclaw-security" in captured.err


def test_report_runtime_hook_opt_out_points_adapters_at_reenable(
    install_module: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert install_module._runtime_hook_plan("goose", False) is None
    exit_code = install_module._report_runtime_hook("goose", False, None)

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Re-run without --no-enable-runtime-hooks" in captured.out


def test_runtime_hooks_default_on_with_opt_out_flag(install_module: Any) -> None:
    parser = install_module.build_parser()

    assert parser.parse_args(["openclaw"]).enable_runtime_hooks is True
    assert parser.parse_args(["openclaw", "--no-enable-runtime-hooks"]).enable_runtime_hooks is False
