"""
tests/test_export_openapi.py

Unit tests for scripts/export_openapi.py

Covers:
- load_app() singleton path (app.main.app)
- load_app() fallback path (app.main.create_app)
- load_app() returns None when all imports fail
- validate_openapi_schema() happy path
- validate_openapi_schema() missing required fields
- validate_openapi_schema() non-3.x version rejection
- count_routes() correct integer counting
- serialize_schema() valid JSON, sorted keys, trailing newline
- write_schema_file() atomic write, .json.bak backup, .tmp cleanup on bad JSON
- main() exit codes across all success and failure paths
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

# Ensure scripts/ is importable before any from-imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# ruff: noqa: E402
from scripts.export_openapi import (  # noqa: E402
    count_routes,
    extract_openapi_schema,
    load_app,
    main,
    serialize_schema,
    validate_openapi_schema,
    write_schema_file,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_SCHEMA: dict = {
    "openapi": "3.1.0",
    "info": {"title": "IronClaw", "version": "1.0.0"},
    "paths": {
        "/health": {"get": {"summary": "Health"}},
        "/api/v1/guard/inspect": {
            "post": {"summary": "Inspect"},
            "get": {"summary": "List"},
        },
    },
}


def _make_mock_app(schema: dict | None = None) -> MagicMock:
    app = MagicMock()
    app.openapi.return_value = schema if schema is not None else VALID_SCHEMA
    return app


# ---------------------------------------------------------------------------
# load_app()
# ---------------------------------------------------------------------------


class TestLoadApp:
    def test_returns_singleton_app_from_app_main(self):
        mock_app = _make_mock_app()

        with patch.dict("sys.modules", {"app": MagicMock(), "app.main": MagicMock(app=mock_app)}):
            result = load_app()

        assert result is mock_app

    def test_falls_back_to_create_app_when_app_attr_missing(self):
        mock_app = _make_mock_app()
        mock_factory = MagicMock(return_value=mock_app)

        main_module = MagicMock(spec=[])
        main_module.create_app = mock_factory

        with patch.dict("sys.modules", {"app": MagicMock(), "app.main": main_module}):
            result = load_app()

        assert result is not None

    def test_returns_none_when_both_imports_fail(self, capsys):
        with patch.dict("sys.modules", {"app": None, "app.main": None}):
            result = load_app()

        assert result is None
        captured = capsys.readouterr()
        assert "ERROR" in captured.err

    def test_returns_none_on_unexpected_exception(self, capsys):
        mock_main = MagicMock()
        del mock_main.app
        del mock_main.create_app

        with patch.dict("sys.modules", {"app": MagicMock(), "app.main": mock_main}):
            result = load_app()

        assert result is None


# ---------------------------------------------------------------------------
# validate_openapi_schema()
# ---------------------------------------------------------------------------


class TestValidateOpenAPISchema:
    def test_passes_with_valid_schema(self):
        assert validate_openapi_schema(VALID_SCHEMA) is True

    def test_fails_missing_openapi_field(self, capsys):
        schema = {k: v for k, v in VALID_SCHEMA.items() if k != "openapi"}
        result = validate_openapi_schema(schema)
        assert result is False
        assert "openapi" in capsys.readouterr().err

    def test_fails_missing_info_field(self, capsys):
        schema = {k: v for k, v in VALID_SCHEMA.items() if k != "info"}
        result = validate_openapi_schema(schema)
        assert result is False
        assert "info" in capsys.readouterr().err

    def test_fails_missing_paths_field(self, capsys):
        schema = {k: v for k, v in VALID_SCHEMA.items() if k != "paths"}
        result = validate_openapi_schema(schema)
        assert result is False
        assert "paths" in capsys.readouterr().err

    def test_fails_non_3x_openapi_version(self, capsys):
        schema = {**VALID_SCHEMA, "openapi": "2.0.0"}
        result = validate_openapi_schema(schema)
        assert result is False
        assert "2.0.0" in capsys.readouterr().err

    def test_fails_info_not_dict(self, capsys):
        schema = {**VALID_SCHEMA, "info": "not-a-dict"}
        result = validate_openapi_schema(schema)
        assert result is False
        assert "info" in capsys.readouterr().err

    def test_fails_paths_not_dict(self, capsys):
        schema = {**VALID_SCHEMA, "paths": ["not", "a", "dict"]}
        result = validate_openapi_schema(schema)
        assert result is False
        assert "paths" in capsys.readouterr().err

    def test_accepts_3_0_0_version(self):
        schema = {**VALID_SCHEMA, "openapi": "3.0.0"}
        assert validate_openapi_schema(schema) is True

    def test_accepts_3_1_0_version(self):
        schema = {**VALID_SCHEMA, "openapi": "3.1.0"}
        assert validate_openapi_schema(schema) is True


# ---------------------------------------------------------------------------
# count_routes()
# ---------------------------------------------------------------------------


class TestCountRoutes:
    def test_counts_all_http_methods(self):
        schema = {
            "paths": {
                "/a": {"get": {}, "post": {}},
                "/b": {"put": {}, "delete": {}, "patch": {}},
                "/c": {"options": {}, "head": {}, "trace": {}},
            }
        }
        assert count_routes(schema) == 8

    def test_ignores_non_method_keys(self):
        schema = {
            "paths": {
                "/a": {
                    "get": {},
                    "summary": "ignored",
                    "parameters": [],
                    "x-custom": "ignored",
                }
            }
        }
        assert count_routes(schema) == 1

    def test_empty_paths_returns_zero(self):
        assert count_routes({"paths": {}}) == 0

    def test_missing_paths_key_returns_zero(self):
        assert count_routes({}) == 0

    def test_valid_schema_fixture_count(self):
        assert count_routes(VALID_SCHEMA) == 3


# ---------------------------------------------------------------------------
# serialize_schema()
# ---------------------------------------------------------------------------


class TestSerializeSchema:
    def test_produces_valid_json(self):
        result = serialize_schema(VALID_SCHEMA)
        parsed = json.loads(result)
        assert parsed["openapi"] == VALID_SCHEMA["openapi"]

    def test_ends_with_trailing_newline(self):
        result = serialize_schema(VALID_SCHEMA)
        assert result.endswith("\n")

    def test_keys_are_sorted(self):
        schema = {"z": 1, "a": 2, "m": 3}
        result = serialize_schema(schema)
        parsed_keys = list(json.loads(result).keys())
        assert parsed_keys == sorted(parsed_keys)

    def test_uses_two_space_indent(self):
        schema = {"openapi": "3.1.0", "info": {}, "paths": {}}
        result = serialize_schema(schema)
        assert '  "info"' in result

    def test_non_ascii_preserved(self):
        schema = {**VALID_SCHEMA, "description": "Sécurité ñ"}
        result = serialize_schema(schema)
        assert "Sécurité" in result


# ---------------------------------------------------------------------------
# write_schema_file()
# ---------------------------------------------------------------------------


class TestWriteSchemaFile:
    def test_writes_file_successfully(self, tmp_path):
        output = tmp_path / "openapi.json"
        schema_json = serialize_schema(VALID_SCHEMA)
        result = write_schema_file(output, schema_json)
        assert result is True
        assert output.exists()
        assert json.loads(output.read_text())["openapi"] == "3.1.0"

    def test_creates_backup_when_file_exists(self, tmp_path):
        output = tmp_path / "openapi.json"
        output.write_text('{"openapi":"3.0.0","info":{},"paths":{}}', encoding="utf-8")
        schema_json = serialize_schema(VALID_SCHEMA)
        write_schema_file(output, schema_json)
        backup = tmp_path / "openapi.json.bak"
        assert backup.exists()
        assert '"3.0.0"' in backup.read_text()

    def test_cleans_up_tmp_on_bad_json(self, tmp_path, capsys):
        output = tmp_path / "openapi.json"
        result = write_schema_file(output, "NOT VALID JSON {{{{")
        assert result is False
        assert not (tmp_path / "openapi.tmp").exists()
        assert "ERROR" in capsys.readouterr().err

    def test_no_backup_when_output_does_not_exist(self, tmp_path):
        output = tmp_path / "openapi.json"
        schema_json = serialize_schema(VALID_SCHEMA)
        write_schema_file(output, schema_json)
        backup = tmp_path / "openapi.json.bak"
        assert not backup.exists()

    def test_atomic_write_final_content_correct(self, tmp_path):
        output = tmp_path / "schema.json"
        schema_json = serialize_schema(VALID_SCHEMA)
        write_schema_file(output, schema_json)
        written = json.loads(output.read_text())
        assert written["info"]["title"] == "IronClaw"


# ---------------------------------------------------------------------------
# extract_openapi_schema()
# ---------------------------------------------------------------------------


class TestExtractOpenAPISchema:
    def test_returns_schema_from_app_openapi(self):
        mock_app = _make_mock_app()
        result = extract_openapi_schema(mock_app)
        assert result == VALID_SCHEMA

    def test_returns_none_on_exception(self, capsys):
        mock_app = MagicMock()
        mock_app.openapi.side_effect = RuntimeError("schema build failed")
        result = extract_openapi_schema(mock_app)
        assert result is None
        assert "ERROR" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


class TestMain:
    def _run_main(self, argv: list[str], mock_app=None) -> int:
        target_app = mock_app if mock_app is not None else _make_mock_app()
        with patch("sys.argv", ["export_openapi"] + argv):
            with patch("scripts.export_openapi.load_app", return_value=target_app):
                return main()

    def test_returns_0_on_success(self, tmp_path):
        output = tmp_path / "out.json"
        result = self._run_main(["--output", str(output), "--quiet"])
        assert result == 0
        assert output.exists()

    def test_returns_1_when_app_is_none(self):
        with patch("sys.argv", ["export_openapi", "--quiet"]):
            with patch("scripts.export_openapi.load_app", return_value=None):
                result = main()
        assert result == 1

    def test_returns_1_when_schema_extraction_fails(self):
        mock_app = MagicMock()
        mock_app.openapi.side_effect = RuntimeError("broken")
        with patch("sys.argv", ["export_openapi", "--quiet"]):
            with patch("scripts.export_openapi.load_app", return_value=mock_app):
                result = main()
        assert result == 1

    def test_returns_1_when_schema_invalid(self):
        mock_app = MagicMock()
        mock_app.openapi.return_value = {"openapi": "2.0.0", "info": {}, "paths": {}}
        with patch("sys.argv", ["export_openapi", "--quiet"]):
            with patch("scripts.export_openapi.load_app", return_value=mock_app):
                result = main()
        assert result == 1

    def test_returns_1_when_write_fails(self, tmp_path):
        output = tmp_path / "openapi.json"
        with patch("sys.argv", ["export_openapi", "--output", str(output), "--quiet"]):
            with patch("scripts.export_openapi.load_app", return_value=_make_mock_app()):
                with patch("scripts.export_openapi.write_schema_file", return_value=False):
                    result = main()
        assert result == 1

    def test_validate_mode_returns_0_without_writing(self, tmp_path):
        output = tmp_path / "openapi.json"
        with patch("sys.argv", ["export_openapi", "--validate", "--quiet", "--output", str(output)]):
            with patch("scripts.export_openapi.load_app", return_value=_make_mock_app()):
                result = main()
        assert result == 0
        assert not output.exists()

    def test_quiet_flag_suppresses_stdout(self, tmp_path, capsys):
        output = tmp_path / "openapi.json"
        self._run_main(["--output", str(output), "--quiet"])
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_non_quiet_prints_success_info(self, tmp_path, capsys):
        output = tmp_path / "openapi.json"
        self._run_main(["--output", str(output)])
        captured = capsys.readouterr()
        assert "SUCCESS" in captured.out
        assert "routes" in captured.out.lower()
