from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.routing import APIRoute

from app.main import app

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_FILE = ROOT / ".route-inventory.json"


def _normalize(value: Any) -> str:
    if isinstance(value, str):
        return value
    if hasattr(value, "value"):
        return str(value.value)
    if hasattr(value, "name"):
        return str(value.name)
    return str(value)


def _dependency_name(dep: Any) -> str:
    call = getattr(dep, "call", None)
    if call is None:
        return "unknown"
    return getattr(call, "__name__", call.__class__.__name__)


def _route_auth_flags(route: APIRoute) -> dict[str, Any]:
    dependency_names = [_dependency_name(dep) for dep in route.dependant.dependencies]
    lowered = [name.lower() for name in dependency_names]

    auth_markers = (
        "auth",
        "token",
        "apikey",
        "api_key",
        "jwt",
        "bearer",
        "session",
        "current_user",
        "currentuser",
        "permission",
        "scope",
        "guard",
        "security",
    )

    auth_dependency_names = [name for name, lowered_name in zip(dependency_names, lowered, strict=False) if any(marker in lowered_name for marker in auth_markers)]

    has_auth_dependency = bool(auth_dependency_names)
    return {
        "has_auth_dependency": has_auth_dependency,
        "auth_dependency_names": auth_dependency_names,
        "dependency_names": dependency_names,
    }


def _inventory() -> dict[str, Any]:
    routes: list[dict[str, Any]] = []

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue

        methods = sorted(method for method in (route.methods or set()) if method != "HEAD")
        tags = [_normalize(tag) for tag in (route.tags or [])]
        auth_flags = _route_auth_flags(route)

        routes.append(
            {
                "name": route.name,
                "path": route.path,
                "methods": methods,
                "tags": tags,
                "operation_id": route.operation_id,
                "include_in_schema": route.include_in_schema,
                "summary": route.summary,
                "deprecated": bool(route.deprecated),
                "response_model": (getattr(route.response_model, "__name__", str(route.response_model)) if route.response_model is not None else None),
                "has_path_params": "{" in route.path and "}" in route.path,
                **auth_flags,
            },
        )

    routes.sort(key=lambda item: (item["path"], ",".join(item["methods"])))

    tag_index: dict[str, int] = {}
    auth_required_count = 0

    for route in routes:
        for tag in route["tags"]:
            tag_index[tag] = tag_index.get(tag, 0) + 1
        if route["has_auth_dependency"]:
            auth_required_count += 1

    return {
        "status": "ok",
        "route_count": len(routes),
        "schema_route_count": sum(1 for route in routes if route["include_in_schema"]),
        "auth_required_count": auth_required_count,
        "tag_index": dict(sorted(tag_index.items())),
        "routes": routes,
    }


def main() -> None:
    payload = _inventory()
    OUTPUT_FILE.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    print(f"Route inventory written to {OUTPUT_FILE}")
    print(f"Routes discovered: {payload['route_count']}")
    print(f"Schema routes: {payload['schema_route_count']}")
    print(f"Routes with auth markers: {payload['auth_required_count']}")


if __name__ == "__main__":
    main()
