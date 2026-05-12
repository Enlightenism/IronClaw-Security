from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
ROOT_API_DIR: Final[Path] = REPO_ROOT / "api"
APP_API_DIR: Final[Path] = REPO_ROOT / "app" / "api"
APP_UI_DIR: Final[Path] = REPO_ROOT / "app" / "ui"
APP_ROUTES_DIR: Final[Path] = REPO_ROOT / "app" / "routes"
IRONCLAW_API_DIR: Final[Path] = REPO_ROOT / "ironclaw" / "routes"
RESULT_FILE: Final[Path] = REPO_ROOT / ".route-inventory.json"

IGNORED_FILES: Final[set[str]] = {"__init__.py", "main.py", "bootstrap.py"}
IGNORED_DIR_NAMES: Final[set[str]] = {
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
}
PYTHON_SUFFIX: Final[str] = ".py"


@dataclass(frozen=True, slots=True)
class RouteModule:
    layer: str
    surface: str
    path: str
    file_name: str
    stem: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RouteInventory:
    repository_root: str
    result_file: str
    module_count: int
    modules: tuple[RouteModule, ...]
    summary: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_root": self.repository_root,
            "result_file": self.result_file,
            "module_count": self.module_count,
            "modules": [module.to_dict() for module in self.modules],
            "summary": dict(self.summary),
        }


@dataclass(frozen=True, slots=True)
class ScanTarget:
    root: Path
    surface: str
    layer: str


SCAN_TARGETS: Final[tuple[ScanTarget, ...]] = (
    ScanTarget(root=ROOT_API_DIR, surface="root-api", layer="api"),
    ScanTarget(root=APP_API_DIR, surface="app-api", layer="api"),
    ScanTarget(root=IRONCLAW_API_DIR, surface="ironclaw-routes", layer="api"),
    ScanTarget(root=APP_ROUTES_DIR, surface="app-routes", layer="api"),
    ScanTarget(root=APP_UI_DIR, surface="ui", layer="ui"),
)


def _to_posix(path: Path) -> str:
    return path.as_posix()


def _should_ignore(path: Path) -> bool:
    return path.name in IGNORED_FILES or any(part in IGNORED_DIR_NAMES for part in path.parts)


def _iter_python_files(target: ScanTarget) -> list[RouteModule]:
    if not target.root.exists() or not target.root.is_dir():
        return []

    modules: list[RouteModule] = []
    for path in sorted(target.root.rglob(f"*{PYTHON_SUFFIX}")):
        if not path.is_file():
            continue
        if _should_ignore(path):
            continue

        rel = path.relative_to(REPO_ROOT)
        modules.append(
            RouteModule(
                layer=target.layer,
                surface=target.surface,
                path=_to_posix(rel),
                file_name=path.name,
                stem=path.stem,
            )
        )

    return modules


def _collect_inventory(output_file: Path) -> RouteInventory:
    modules: list[RouteModule] = []
    for target in SCAN_TARGETS:
        modules.extend(_iter_python_files(target))

    modules = sorted(modules, key=lambda module: (module.layer, module.surface, module.path))

    summary: dict[str, int] = {}
    for module in modules:
        key = f"{module.layer}:{module.surface}"
        summary[key] = summary.get(key, 0) + 1

    return RouteInventory(
        repository_root=_to_posix(REPO_ROOT),
        result_file=_to_posix(output_file),
        module_count=len(modules),
        modules=tuple(modules),
        summary=dict(sorted(summary.items())),
    )


def _write_inventory(inventory: RouteInventory, output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(inventory.to_dict(), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Emit a JSON inventory of IronClaw route modules for audit coverage and regression tracking."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the inventory JSON to stdout in addition to writing the result file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULT_FILE,
        help="Write inventory JSON to the specified file path.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    output_file = args.output.expanduser().resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    inventory = _collect_inventory(output_file)
    _write_inventory(inventory, output_file)

    if args.json:
        print(json.dumps(inventory.to_dict(), indent=2))

    print(f"Route inventory written to {output_file}")
    print(f"Discovered {inventory.module_count} route modules across {len(inventory.summary)} surfaces.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())