from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ironclaw_skill import __version__
from ironclaw_skill.cli import (
    IronClawSkillCliError,
    SkillDoctorResult,
    SkillStatus,
    _cmd_doctor,
    _cmd_install,
    _cmd_status,
    _cmd_version,
    _derive_status,
    _doctor,
    _load_json_file,
    _print_json,
    build_parser,
    main,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _args(**kwargs: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "json": False,
        "project_root": Path("/tmp/ironclaw_test_project"),
        "config_dir": Path("/tmp/ironclaw_test_config"),
        "base_url": "http://127.0.0.1:8000",
        "backup_target": "primary",
        "restore_target": "primary",
        "retention_days": 30,
        "no_vscode": False,
        "no_skill_config": False,
        "no_env": False,
        "overwrite": False,
        "command": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_fake_install_result(
    config_dir: Path,
    env_file: Path | None = None,
    vscode_settings_file: Path | None = None,
) -> MagicMock:
    result = MagicMock()
    result.config_file = config_dir / "config.json"
    result.env_file = env_file
    result.vscode_settings_file = vscode_settings_file
    result.to_dict.return_value = {
        "config_file": str(config_dir / "config.json"),
        "env_file": str(env_file) if env_file else None,
        "vscode_settings_file": str(vscode_settings_file) if vscode_settings_file else None,
        "ok": True,
    }
    return result


# ---------------------------------------------------------------------------
# build_parser — structure and argument coverage
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_returns_argument_parser_instance(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_prog_name_is_ironclaw_skill(self):
        parser = build_parser()
        assert parser.prog == "ironclaw-skill"

    def test_top_level_json_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--json", "version"])
        assert args.json is True

    def test_json_flag_defaults_false(self):
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert args.json is False

    def test_subcommand_install_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["install"])
        assert args.command == "install"

    def test_subcommand_status_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"

    def test_subcommand_doctor_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["doctor"])
        assert args.command == "doctor"

    def test_subcommand_version_parsed(self):
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert args.command == "version"

    def test_no_subcommand_sets_command_to_none(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert not getattr(args, "command", None)

    def test_install_project_root_accepts_path(self, tmp_path: Path):
        parser = build_parser()
        args = parser.parse_args(["install", "--project-root", str(tmp_path)])
        assert args.project_root == tmp_path

    def test_install_config_dir_accepts_path(self, tmp_path: Path):
        parser = build_parser()
        args = parser.parse_args(["install", "--config-dir", str(tmp_path)])
        assert args.config_dir == tmp_path

    def test_install_base_url_accepts_value(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--base-url", "http://192.168.1.1:9000"])
        assert args.base_url == "http://192.168.1.1:9000"

    def test_install_no_vscode_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--no-vscode"])
        assert args.no_vscode is True

    def test_install_no_skill_config_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--no-skill-config"])
        assert args.no_skill_config is True

    def test_install_no_env_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--no-env"])
        assert args.no_env is True

    def test_install_overwrite_flag(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--overwrite"])
        assert args.overwrite is True

    def test_install_retention_days_accepts_int(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--retention-days", "90"])
        assert args.retention_days == 90

    def test_install_backup_target_accepts_value(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--backup-target", "secondary"])
        assert args.backup_target == "secondary"

    def test_install_restore_target_accepts_value(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--restore-target", "archive"])
        assert args.restore_target == "archive"

    def test_install_func_is_set(self):
        parser = build_parser()
        args = parser.parse_args(["install"])
        assert hasattr(args, "func")
        assert callable(args.func)

    def test_status_func_is_set(self):
        parser = build_parser()
        args = parser.parse_args(["status"])
        assert hasattr(args, "func")
        assert callable(args.func)

    def test_doctor_func_is_set(self):
        parser = build_parser()
        args = parser.parse_args(["doctor"])
        assert hasattr(args, "func")
        assert callable(args.func)

    def test_version_func_is_set(self):
        parser = build_parser()
        args = parser.parse_args(["version"])
        assert hasattr(args, "func")
        assert callable(args.func)


# ---------------------------------------------------------------------------
# main() — exit code routing
# ---------------------------------------------------------------------------


class TestMain:
    def test_no_subcommand_returns_1(self):
        code = main([])
        assert code == 1

    def test_version_subcommand_returns_0(self):
        code = main(["version"])
        assert code == 0

    def test_status_subcommand_returns_0_with_env_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        code = main(["status"])
        assert code == 0

    def test_doctor_returns_nonzero_when_config_dir_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        missing_dir = tmp_path / "nonexistent_config"
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(missing_dir))
        code = main(["doctor"])
        assert code != 0

    def test_ironclaw_cli_error_returns_1(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))

        def bad_func(_: argparse.Namespace) -> int:
            raise IronClawSkillCliError("test error")

        parser = build_parser()
        original_parse_args = parser.parse_args

        def patched_parse_args(argv=None):
            result = original_parse_args(argv)
            result.func = bad_func
            return result

        with patch("ironclaw_skill.cli.build_parser") as mock_parser_factory:
            mock_parser = MagicMock()
            mock_parser.parse_args.return_value = _args(command="status", func=bad_func)
            mock_parser_factory.return_value = mock_parser
            code = main(["status"])
        assert code == 1

    def test_unexpected_exception_returns_1(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))

        def crashing_func(_: argparse.Namespace) -> int:
            raise RuntimeError("unexpected crash")

        with patch("ironclaw_skill.cli.build_parser") as mock_parser_factory:
            mock_parser = MagicMock()
            mock_parser.parse_args.return_value = _args(command="version", func=crashing_func)
            mock_parser_factory.return_value = mock_parser
            code = main(["version"])
        assert code == 1

    def test_json_flag_passed_through_to_status(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        code = main(["--json", "status"])
        captured = capsys.readouterr()
        assert code == 0
        payload = json.loads(captured.out)
        assert "installed" in payload
        assert "version" in payload

    def test_json_flag_passed_through_to_doctor(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        code = main(["--json", "doctor"])
        captured = capsys.readouterr()
        assert isinstance(code, int)
        payload = json.loads(captured.out)
        assert "ok" in payload
        assert "checks" in payload

    def test_json_flag_version_subcommand_prints_version_string(self, capsys):
        code = main(["version"])
        captured = capsys.readouterr()
        assert code == 0
        assert __version__ in captured.out.strip()


# ---------------------------------------------------------------------------
# _cmd_version
# ---------------------------------------------------------------------------


class TestCmdVersion:
    def test_prints_version_string(self, capsys):
        code = _cmd_version(_args())
        captured = capsys.readouterr()
        assert code == 0
        assert __version__ in captured.out

    def test_version_output_is_single_line(self, capsys):
        _cmd_version(_args())
        captured = capsys.readouterr()
        lines = [l for l in captured.out.strip().splitlines() if l.strip()]
        assert len(lines) == 1


# ---------------------------------------------------------------------------
# _cmd_status
# ---------------------------------------------------------------------------


class TestCmdStatus:
    def test_returns_0(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        code = _cmd_status(_args(json=False))
        assert code == 0

    def test_human_output_contains_installed_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_status(_args(json=False))
        captured = capsys.readouterr()
        assert "installed:" in captured.out

    def test_human_output_contains_version_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_status(_args(json=False))
        captured = capsys.readouterr()
        assert "version:" in captured.out

    def test_human_output_contains_config_dir_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_status(_args(json=False))
        captured = capsys.readouterr()
        assert "config_dir:" in captured.out

    def test_human_output_contains_base_url_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_status(_args(json=False))
        captured = capsys.readouterr()
        assert "base_url:" in captured.out

    def test_json_output_is_valid_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        code = _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        assert code == 0
        payload = json.loads(captured.out)
        assert isinstance(payload, dict)

    def test_json_output_installed_field_is_bool(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert isinstance(payload["installed"], bool)

    def test_json_output_version_matches_package(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["version"] == __version__

    def test_installed_false_when_config_dir_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        missing = tmp_path / "missing_dir"
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(missing))
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["installed"] is False

    def test_installed_false_when_only_config_file_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["installed"] is False

    def test_installed_true_when_both_config_and_skill_exist(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / "skill.json").write_text("{}", encoding="utf-8")
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["installed"] is True

    def test_base_url_read_from_config_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        config_payload = {"base_url": "http://10.0.0.1:7777"}
        (tmp_path / "config.json").write_text(json.dumps(config_payload), encoding="utf-8")
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["base_url"] == "http://10.0.0.1:7777"

    def test_base_url_env_overrides_config_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://env-override:5000")
        config_payload = {"base_url": "http://file-value:8000"}
        (tmp_path / "config.json").write_text(json.dumps(config_payload), encoding="utf-8")
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["base_url"] == "http://env-override:5000"

    def test_base_url_none_when_not_configured(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["base_url"] is None

    def test_human_unset_base_url_prints_unset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        _cmd_status(_args(json=False))
        captured = capsys.readouterr()
        assert "unset" in captured.out


# ---------------------------------------------------------------------------
# _cmd_doctor
# ---------------------------------------------------------------------------


class TestCmdDoctor:
    def test_returns_1_when_config_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        missing = tmp_path / "no_such_dir"
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(missing))
        code = _cmd_doctor(_args(json=False))
        assert code == 1

    def test_returns_0_when_all_checks_pass(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000")

        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / "skill.json").write_text("{}", encoding="utf-8")

        with patch("ironclaw_skill.cli._project_root") as mock_root, \
             patch("ironclaw_skill.cli._env_file") as mock_env:
            mock_root.return_value = tmp_path
            mock_env.return_value = tmp_path / ".env"
            (tmp_path / ".env").write_text("# env\n", encoding="utf-8")
            code = _cmd_doctor(_args(json=False))
        assert code == 0

    def test_human_output_ok_label_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000")
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / "skill.json").write_text("{}", encoding="utf-8")

        with patch("ironclaw_skill.cli._project_root", return_value=tmp_path), \
             patch("ironclaw_skill.cli._env_file", return_value=tmp_path / ".env"):
            (tmp_path / ".env").write_text("# env\n", encoding="utf-8")
            _cmd_doctor(_args(json=False))

        captured = capsys.readouterr()
        assert "[OK]" in captured.out or "[FAIL]" in captured.out

    def test_human_output_fail_label_present_when_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        missing = tmp_path / "absent"
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(missing))
        _cmd_doctor(_args(json=False))
        captured = capsys.readouterr()
        assert "[FAIL]" in captured.out

    def test_json_output_is_valid_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert isinstance(payload, dict)

    def test_json_output_has_ok_field(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert "ok" in payload
        assert isinstance(payload["ok"], bool)

    def test_json_output_has_checks_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert "checks" in payload
        assert isinstance(payload["checks"], list)
        assert len(payload["checks"]) > 0

    def test_checks_each_have_name_ok_detail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        for check in payload["checks"]:
            assert "name" in check
            assert "ok" in check
            assert "detail" in check

    def test_doctor_check_names_include_expected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        names = {c["name"] for c in payload["checks"]}
        assert "config-file" in names
        assert "skill-file" in names
        assert "base-url" in names

    def test_ok_false_when_config_file_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        missing = tmp_path / "no_dir"
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(missing))
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["ok"] is False

    def test_ok_true_when_all_checks_pass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000")
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / "skill.json").write_text("{}", encoding="utf-8")

        with patch("ironclaw_skill.cli._project_root", return_value=tmp_path), \
             patch("ironclaw_skill.cli._env_file", return_value=tmp_path / ".env"):
            (tmp_path / ".env").write_text("# env\n", encoding="utf-8")
            _cmd_doctor(_args(json=True))

        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["ok"] is True

    def test_base_url_check_fails_when_env_missing_and_config_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        base_url_check = next(c for c in payload["checks"] if c["name"] == "base-url")
        assert base_url_check["ok"] is False

    def test_base_url_check_passes_when_env_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000")
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        base_url_check = next(c for c in payload["checks"] if c["name"] == "base-url")
        assert base_url_check["ok"] is True


# ---------------------------------------------------------------------------
# _cmd_install
# ---------------------------------------------------------------------------


class TestCmdInstall:
    def _make_mock_run_install(self, tmp_path: Path) -> MagicMock:
        return MagicMock(return_value=_make_fake_install_result(tmp_path))

    def test_returns_0_on_success(self, tmp_path: Path):
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            mock_config.return_value = MagicMock()
            args = _args(
                command="install",
                project_root=tmp_path,
                config_dir=tmp_path,
                json=False,
            )
            code = _cmd_install(args)
        assert code == 0

    def test_human_output_contains_install_completed(self, tmp_path: Path, capsys):
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=False)
            _cmd_install(args)
        captured = capsys.readouterr()
        assert "install completed" in captured.out

    def test_human_output_contains_config_file_path(self, tmp_path: Path, capsys):
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=False)
            _cmd_install(args)
        captured = capsys.readouterr()
        assert "config file:" in captured.out

    def test_human_output_contains_env_file_when_written(self, tmp_path: Path, capsys):
        env_path = tmp_path / ".env"
        mock_result = _make_fake_install_result(tmp_path, env_file=env_path)
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", return_value=mock_result):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=False)
            _cmd_install(args)
        captured = capsys.readouterr()
        assert "env file:" in captured.out

    def test_human_output_omits_env_file_when_not_written(self, tmp_path: Path, capsys):
        mock_result = _make_fake_install_result(tmp_path, env_file=None)
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", return_value=mock_result):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=False)
            _cmd_install(args)
        captured = capsys.readouterr()
        assert "env file:" not in captured.out

    def test_human_output_contains_vscode_settings_when_written(self, tmp_path: Path, capsys):
        vscode_path = tmp_path / ".vscode" / "settings.json"
        mock_result = _make_fake_install_result(tmp_path, vscode_settings_file=vscode_path)
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", return_value=mock_result):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=False)
            _cmd_install(args)
        captured = capsys.readouterr()
        assert "vscode settings:" in captured.out

    def test_human_output_omits_vscode_when_not_written(self, tmp_path: Path, capsys):
        mock_result = _make_fake_install_result(tmp_path, vscode_settings_file=None)
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", return_value=mock_result):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=False)
            _cmd_install(args)
        captured = capsys.readouterr()
        assert "vscode settings:" not in captured.out

    def test_json_output_is_valid_json(self, tmp_path: Path, capsys):
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=True)
            code = _cmd_install(args)
        captured = capsys.readouterr()
        assert code == 0
        payload = json.loads(captured.out)
        assert isinstance(payload, dict)

    def test_json_output_has_ok_field(self, tmp_path: Path, capsys):
        with patch("ironclaw_skill.cli.build_install_config") as mock_config, \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            mock_config.return_value = MagicMock()
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, json=True)
            _cmd_install(args)
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert "ok" in payload

    def test_build_install_config_called_with_namespace(self, tmp_path: Path):
        captured_args: list[argparse.Namespace] = []

        def capture_config(ns):
            captured_args.append(ns)
            return MagicMock()

        with patch("ironclaw_skill.cli.build_install_config", side_effect=capture_config), \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path)
            _cmd_install(args)

        assert len(captured_args) == 1
        ns = captured_args[0]
        assert ns.project_root == tmp_path
        assert ns.config_dir == tmp_path
        assert ns.overwrite is False
        assert ns.no_vscode is False
        assert ns.no_skill_config is False
        assert ns.no_env is False

    def test_no_vscode_true_passed_to_installer(self, tmp_path: Path):
        captured_args: list[argparse.Namespace] = []

        def capture_config(ns):
            captured_args.append(ns)
            return MagicMock()

        with patch("ironclaw_skill.cli.build_install_config", side_effect=capture_config), \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, no_vscode=True)
            _cmd_install(args)

        assert captured_args[0].no_vscode is True

    def test_overwrite_true_passed_to_installer(self, tmp_path: Path):
        captured_args: list[argparse.Namespace] = []

        def capture_config(ns):
            captured_args.append(ns)
            return MagicMock()

        with patch("ironclaw_skill.cli.build_install_config", side_effect=capture_config), \
             patch("ironclaw_skill.cli.run_install", self._make_mock_run_install(tmp_path)):
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path, overwrite=True)
            _cmd_install(args)

        assert captured_args[0].overwrite is True

    def test_run_install_called_once(self, tmp_path: Path):
        mock_run = MagicMock(return_value=_make_fake_install_result(tmp_path))
        with patch("ironclaw_skill.cli.build_install_config", return_value=MagicMock()), \
             patch("ironclaw_skill.cli.run_install", mock_run):
            args = _args(command="install", project_root=tmp_path, config_dir=tmp_path)
            _cmd_install(args)
        assert mock_run.call_count == 1


# ---------------------------------------------------------------------------
# _load_json_file
# ---------------------------------------------------------------------------


class TestLoadJsonFile:
    def test_returns_empty_dict_for_missing_file(self, tmp_path: Path):
        result = _load_json_file(tmp_path / "no_such_file.json")
        assert result == {}

    def test_returns_parsed_dict_for_valid_json(self, tmp_path: Path):
        path = tmp_path / "test.json"
        path.write_text(json.dumps({"key": "value"}), encoding="utf-8")
        result = _load_json_file(path)
        assert result == {"key": "value"}

    def test_raises_for_non_dict_json(self, tmp_path: Path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        with pytest.raises(IronClawSkillCliError, match="Expected JSON object"):
            _load_json_file(path)

    def test_raises_for_invalid_json(self, tmp_path: Path):
        path = tmp_path / "corrupt.json"
        path.write_text("{not valid json}", encoding="utf-8")
        with pytest.raises(Exception):
            _load_json_file(path)

    def test_returns_empty_dict_for_empty_object(self, tmp_path: Path):
        path = tmp_path / "empty.json"
        path.write_text("{}", encoding="utf-8")
        result = _load_json_file(path)
        assert result == {}

    def test_preserves_nested_values(self, tmp_path: Path):
        data = {"a": {"b": {"c": 42}}, "list": [1, 2, 3]}
        path = tmp_path / "nested.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        result = _load_json_file(path)
        assert result["a"]["b"]["c"] == 42
        assert result["list"] == [1, 2, 3]


# ---------------------------------------------------------------------------
# _derive_status
# ---------------------------------------------------------------------------


class TestDeriveStatus:
    def test_returns_skill_status_instance(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _derive_status()
        assert isinstance(result, SkillStatus)

    def test_installed_false_when_files_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _derive_status()
        assert result.installed is False

    def test_installed_true_when_both_files_exist(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        (tmp_path / "config.json").write_text("{}", encoding="utf-8")
        (tmp_path / "skill.json").write_text("{}", encoding="utf-8")
        result = _derive_status()
        assert result.installed is True

    def test_version_matches_package_version(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _derive_status()
        assert result.version == __version__

    def test_base_url_from_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://env-url:9999")
        result = _derive_status()
        assert result.base_url == "http://env-url:9999"

    def test_base_url_trailing_slash_stripped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://env-url:9999/")
        result = _derive_status()
        assert result.base_url == "http://env-url:9999"

    def test_base_url_none_when_not_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        result = _derive_status()
        assert result.base_url is None

    def test_base_url_from_config_file_when_env_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        (tmp_path / "config.json").write_text(json.dumps({"base_url": "http://from-file:8080"}), encoding="utf-8")
        result = _derive_status()
        assert result.base_url == "http://from-file:8080"

    def test_config_dir_matches_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _derive_status()
        assert result.config_dir == tmp_path.resolve()

    def test_to_dict_all_paths_are_strings(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _derive_status()
        d = result.to_dict()
        for key in ("config_dir", "config_file", "skill_file", "env_file"):
            assert isinstance(d[key], str), f"{key} should be a string"

    def test_to_dict_contains_expected_keys(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _derive_status()
        d = result.to_dict()
        for key in ("installed", "version", "config_dir", "config_file", "skill_file", "env_file", "base_url"):
            assert key in d


# ---------------------------------------------------------------------------
# _doctor
# ---------------------------------------------------------------------------


class TestDoctor:
    def test_returns_skill_doctor_result_instance(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        assert isinstance(result, SkillDoctorResult)

    def test_ok_false_when_config_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        missing = tmp_path / "absent"
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(missing))
        result = _doctor()
        assert result.ok is False

    def test_checks_is_tuple(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        assert isinstance(result.checks, tuple)

    def test_each_check_is_dict(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        for check in result.checks:
            assert isinstance(check, dict)

    def test_project_root_check_always_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        names = {c["name"] for c in result.checks}
        assert "project-root" in names

    def test_config_file_check_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        names = {c["name"] for c in result.checks}
        assert "config-file" in names

    def test_skill_file_check_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        names = {c["name"] for c in result.checks}
        assert "skill-file" in names

    def test_env_file_check_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        names = {c["name"] for c in result.checks}
        assert "env-file" in names

    def test_base_url_check_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        names = {c["name"] for c in result.checks}
        assert "base-url" in names

    def test_ok_false_aggregated_from_any_failed_check(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        result = _doctor()
        failed = [c for c in result.checks if not c["ok"]]
        if failed:
            assert result.ok is False

    def test_to_dict_has_ok_and_checks(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        result = _doctor()
        d = result.to_dict()
        assert "ok" in d
        assert "checks" in d
        assert isinstance(d["checks"], list)


# ---------------------------------------------------------------------------
# SkillStatus — to_dict and field types
# ---------------------------------------------------------------------------


class TestSkillStatus:
    def _make_status(self, tmp_path: Path) -> SkillStatus:
        return SkillStatus(
            installed=True,
            config_dir=tmp_path,
            config_file=tmp_path / "config.json",
            skill_file=tmp_path / "skill.json",
            env_file=tmp_path / ".env",
            base_url="http://127.0.0.1:8000",
            version="0.1.0",
        )

    def test_to_dict_installed_is_bool(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        d = status.to_dict()
        assert isinstance(d["installed"], bool)

    def test_to_dict_config_dir_is_str(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        d = status.to_dict()
        assert isinstance(d["config_dir"], str)

    def test_to_dict_config_file_is_str(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        d = status.to_dict()
        assert isinstance(d["config_file"], str)

    def test_to_dict_skill_file_is_str(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        d = status.to_dict()
        assert isinstance(d["skill_file"], str)

    def test_to_dict_env_file_is_str(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        d = status.to_dict()
        assert isinstance(d["env_file"], str)

    def test_to_dict_version_matches(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        assert status.to_dict()["version"] == "0.1.0"

    def test_to_dict_base_url_matches(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        assert status.to_dict()["base_url"] == "http://127.0.0.1:8000"

    def test_frozen_instance_rejects_mutation(self, tmp_path: Path):
        status = self._make_status(tmp_path)
        with pytest.raises((AttributeError, TypeError)):
            status.installed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# SkillDoctorResult — to_dict
# ---------------------------------------------------------------------------


class TestSkillDoctorResult:
    def _make_result(self, ok: bool = True) -> SkillDoctorResult:
        checks = (
            {"name": "config-file", "ok": ok, "detail": "/some/path/config.json"},
            {"name": "skill-file", "ok": ok, "detail": "/some/path/skill.json"},
        )
        return SkillDoctorResult(ok=ok, checks=checks)

    def test_to_dict_ok_matches(self):
        result = self._make_result(ok=True)
        assert result.to_dict()["ok"] is True

    def test_to_dict_checks_is_list(self):
        result = self._make_result()
        d = result.to_dict()
        assert isinstance(d["checks"], list)

    def test_to_dict_checks_length_matches(self):
        result = self._make_result()
        d = result.to_dict()
        assert len(d["checks"]) == 2

    def test_frozen_instance_rejects_mutation(self):
        result = self._make_result()
        with pytest.raises((AttributeError, TypeError)):
            result.ok = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# _print_json
# ---------------------------------------------------------------------------


class TestPrintJson:
    def test_outputs_sorted_json(self, capsys):
        _print_json({"z": 1, "a": 2, "m": 3})
        captured = capsys.readouterr()
        keys = list(json.loads(captured.out).keys())
        assert keys == sorted(keys)

    def test_outputs_indented_json(self, capsys):
        _print_json({"key": "value"})
        captured = capsys.readouterr()
        assert "\n" in captured.out
        assert "  " in captured.out

    def test_handles_unicode_without_escape(self, capsys):
        _print_json({"message": "IronClaw – Sécurité"})
        captured = capsys.readouterr()
        assert "IronClaw" in captured.out
        assert "\\u" not in captured.out

    def test_nested_dicts_render_correctly(self, capsys):
        _print_json({"outer": {"inner": 42}})
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["outer"]["inner"] == 42

    def test_empty_dict_renders_valid_json(self, capsys):
        _print_json({})
        captured = capsys.readouterr()
        assert json.loads(captured.out) == {}


# ---------------------------------------------------------------------------
# Environment variable integration
# ---------------------------------------------------------------------------


class TestEnvironmentVariableIntegration:
    def test_ironclaw_config_dir_env_controls_status_config_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        custom_dir = tmp_path / "custom_config"
        custom_dir.mkdir()
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(custom_dir))
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert str(custom_dir) in payload["config_dir"]

    def test_ironclaw_base_url_env_reflected_in_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://custom-host:1234")
        _cmd_status(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["base_url"] == "http://custom-host:1234"

    def test_ironclaw_base_url_env_reflected_in_doctor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.setenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000")
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        base_url_check = next(c for c in payload["checks"] if c["name"] == "base-url")
        assert base_url_check["ok"] is True
        assert "http://127.0.0.1:8000" in base_url_check["detail"]

    def test_missing_ironclaw_base_url_env_reflects_in_doctor_detail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        monkeypatch.delenv("IRONCLAW_BASE_URL", raising=False)
        _cmd_doctor(_args(json=True))
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        base_url_check = next(c for c in payload["checks"] if c["name"] == "base-url")
        assert "missing" in base_url_check["detail"].lower() or base_url_check["ok"] is False


# ---------------------------------------------------------------------------
# End-to-end CLI surface via main()
# ---------------------------------------------------------------------------


class TestMainEndToEnd:
    def test_version_output_is_non_empty(self, capsys):
        main(["version"])
        captured = capsys.readouterr()
        assert captured.out.strip() != ""

    def test_status_json_output_is_parseable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        main(["--json", "status"])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert isinstance(payload, dict)

    def test_doctor_json_output_is_parseable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        main(["--json", "doctor"])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert isinstance(payload, dict)

    def test_status_human_output_is_non_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        main(["status"])
        captured = capsys.readouterr()
        assert captured.out.strip() != ""

    def test_doctor_human_output_is_non_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        monkeypatch.setenv("IRONCLAW_CONFIG_DIR", str(tmp_path))
        main(["doctor"])
        captured = capsys.readouterr()
        assert captured.out.strip() != ""

    def test_unknown_subcommand_exits_with_error(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["nonexistent-command"])

    def test_main_install_routes_to_cmd_install(self, tmp_path: Path):
        mock_result = _make_fake_install_result(tmp_path)
        with patch("ironclaw_skill.cli.build_install_config", return_value=MagicMock()), \
             patch("ironclaw_skill.cli.run_install", return_value=mock_result):
            code = main(["install", "--project-root", str(tmp_path), "--config-dir", str(tmp_path)])
        assert code == 0

    def test_main_install_json_routes_to_cmd_install_json(self, tmp_path: Path, capsys):
        mock_result = _make_fake_install_result(tmp_path)
        with patch("ironclaw_skill.cli.build_install_config", return_value=MagicMock()), \
             patch("ironclaw_skill.cli.run_install", return_value=mock_result):
            code = main(["--json", "install", "--project-root", str(tmp_path), "--config-dir", str(tmp_path)])
        captured = capsys.readouterr()
        assert code == 0
        payload = json.loads(captured.out)
        assert "ok" in payload