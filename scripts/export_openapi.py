#!/usr/bin/env python3
"""
scripts/export_openapi.py

Export locked OpenAPI schema on every build.
Ensures API contract stability, enables schema drift detection,
and provides a canonical source of truth for routes, models, and tags.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for OpenAPI export script."""
    parser = argparse.ArgumentParser(
        description="Export OpenAPI schema from IronClaw FastAPI application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("openapi.json"),
        help="Output path for OpenAPI schema JSON file (default: openapi.json)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate schema structure without writing file",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress success output",
    )
    return parser.parse_args()


def load_app():
    """Load FastAPI app instance from app.main or app_init using create_app() factory."""
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        try:
            from app.main import create_app
        except (ImportError, AttributeError):
            try:
                from app.main import app
                return app
            except (ImportError, AttributeError):
                from app_init import create_app

        app = create_app()
        return app
    except ImportError as exc:
        print(f"[export_openapi] ERROR: Failed to import FastAPI app: {exc}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[export_openapi] ERROR: Failed to initialize FastAPI app: {exc}", file=sys.stderr)
        return None


def extract_openapi_schema(app) -> dict[str, Any] | None:
    """Extract OpenAPI 3.1.0 schema from FastAPI app using app.openapi()."""
    try:
        schema = app.openapi()
        return schema
    except Exception as exc:
        print(f"[export_openapi] ERROR: Failed to extract OpenAPI schema: {exc}", file=sys.stderr)
        return None


def validate_openapi_schema(schema: dict[str, Any]) -> bool:
    """Validate OpenAPI schema structure for required fields and OpenAPI 3.1.0 conformance."""
    required_fields = ["openapi", "info", "paths"]
    for field in required_fields:
        if field not in schema:
            print(f"[export_openapi] ERROR: Missing required field '{field}' in OpenAPI schema", file=sys.stderr)
            return False

    if not schema["openapi"].startswith("3."):
        print(f"[export_openapi] ERROR: Unsupported OpenAPI version '{schema['openapi']}', expected 3.x", file=sys.stderr)
        return False

    if not isinstance(schema["info"], dict):
        print("[export_openapi] ERROR: 'info' field must be a dictionary", file=sys.stderr)
        return False

    if not isinstance(schema["paths"], dict):
        print("[export_openapi] ERROR: 'paths' field must be a dictionary", file=sys.stderr)
        return False

    return True


def serialize_schema(schema: dict[str, Any]) -> str:
    """Serialize OpenAPI schema to formatted JSON with 2-space indent, sorted keys, trailing newline."""
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_schema_file(output_path: Path, schema_json: str) -> bool:
    """Write schema to file atomically with backup of existing file."""
    temp_path = output_path.with_suffix(".tmp")

    try:
        temp_path.write_text(schema_json, encoding="utf-8")

        try:
            json.loads(schema_json)
        except json.JSONDecodeError as exc:
            print(f"[export_openapi] ERROR: JSON integrity check failed: {exc}", file=sys.stderr)
            temp_path.unlink(missing_ok=True)
            return False

        if output_path.exists():
            backup_path = output_path.with_suffix(".json.bak")
            shutil.copy2(output_path, backup_path)

        shutil.move(str(temp_path), str(output_path))
        return True

    except Exception as exc:
        print(f"[export_openapi] ERROR: Failed to write schema file: {exc}", file=sys.stderr)
        temp_path.unlink(missing_ok=True)
        return False


def count_routes(schema: dict[str, Any]) -> int:
    """Count total routes in OpenAPI schema."""
    paths = schema.get("paths", {})
    route_count = 0
    for path_item in paths.values():
        if isinstance(path_item, dict):
            route_count += sum(1 for key in path_item if key in {"get", "post", "put", "patch", "delete", "options", "head", "trace"})
    return route_count


def main() -> int:
    """Main entry point for OpenAPI export script."""
    args = parse_args()

    if not args.quiet:
        print(f"[export_openapi] Target output: {args.output}")

    if args.validate:
        if not args.quiet:
            print("[export_openapi] Validation mode enabled - no file will be written")

    app = load_app()
    if app is None:
        return 1

    schema = extract_openapi_schema(app)
    if schema is None:
        return 1

    if not validate_openapi_schema(schema):
        return 1

    schema_json = serialize_schema(schema)

    if args.validate:
        if not args.quiet:
            print("[export_openapi] Schema validation passed")
            print(f"[export_openapi] OpenAPI version: {schema.get('openapi', 'unknown')}")
            print(f"[export_openapi] Total routes: {count_routes(schema)}")
        return 0

    if not write_schema_file(args.output, schema_json):
        return 1

    if not args.quiet:
        file_size = args.output.stat().st_size
        print(f"[export_openapi] SUCCESS: OpenAPI schema exported to {args.output}")
        print(f"[export_openapi] OpenAPI version: {schema.get('openapi', 'unknown')}")
        print(f"[export_openapi] Total routes: {count_routes(schema)}")
        print(f"[export_openapi] File size: {file_size:,} bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())