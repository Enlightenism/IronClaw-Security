from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class PackageCheck:
    name: str
    ok: bool
    detail: str
    recommendation: str | None = None


@dataclass(slots=True)
class PackagePlan:
    product: str
    version: str
    platform: str
    python_executable: str
    source_root: str
    output_dir: str
    artifact_name: str
    format: str
    checks: list[PackageCheck]
    includes: list[str]
    next_steps: list[str]


def _default_source_root() -> Path:
    return Path.cwd()


def _default_output_dir(root: Path) -> Path:
    return root / "dist"


def _python_version_check() -> tuple[bool, str]:
    version = sys.version_info
    ok = (version.major, version.minor) >= (3, 11)
    return ok, f"Detected Python {version.major}.{version.minor}.{version.micro}"


def _path_exists(path: Path) -> tuple[bool, str]:
    ok = path.exists()
    return ok, f"Path: {path}"


def _path_writable(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".package_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, f"Writable: {path}"
    except Exception as exc:
        return False, f"Not writable: {path} ({exc})"


def _build_checks(source_root: Path, output_dir: Path, package_format: str) -> list[PackageCheck]:
    python_ok, python_detail = _python_version_check()
    source_ok, source_detail = _path_exists(source_root)
    output_ok, output_detail = _path_writable(output_dir)
    format_ok = package_format in {"zip", "tar", "directory"}

    return [
        PackageCheck(
            name="python-version",
            ok=python_ok,
            detail=python_detail,
            recommendation=None if python_ok else "Use Python 3.11 or newer before packaging.",
        ),
        PackageCheck(
            name="source-root",
            ok=source_ok,
            detail=source_detail,
            recommendation=None if source_ok else "Run the packaging command from a valid project directory.",
        ),
        PackageCheck(
            name="output-directory",
            ok=output_ok,
            detail=output_detail,
            recommendation=None if output_ok else "Choose a writable output directory.",
        ),
        PackageCheck(
            name="package-format",
            ok=format_ok,
            detail=f"Requested format: {package_format}",
            recommendation=None if format_ok else "Use zip, tar, or directory as the package format.",
        ),
    ]


def build_package_plan(
    source_root: Path | None = None,
    output_dir: Path | None = None,
    package_format: str = "zip",
) -> PackagePlan:
    root = source_root or _default_source_root()
    out_dir = output_dir or _default_output_dir(root)
    normalized_format = package_format.strip().lower()

    checks = _build_checks(root, out_dir, normalized_format)
    artifact_name = f"ironclaw-security-gen1.{'tar.gz' if normalized_format == 'tar' else normalized_format}"

    includes = [
        "app/",
        "core/",
        "ui/",
        "cli/",
        "README.md",
        ".env.example",
    ]

    next_steps = [
        "Verify the package contents before distribution.",
        "Include configuration templates but avoid embedding real secrets.",
        "Run the verify command in a clean environment after unpacking.",
        "Sign or checksum the final artifact if distributing externally.",
    ]

    return PackagePlan(
        product="IronClaw-Security",
        version="gen1",
        platform=platform.platform(),
        python_executable=sys.executable,
        source_root=str(root),
        output_dir=str(out_dir),
        artifact_name=artifact_name,
        format=normalized_format,
        checks=checks,
        includes=includes,
        next_steps=next_steps,
    )


def _render_text(plan: PackagePlan) -> str:
    lines = [
        f"{plan.product} package plan",
        f"version: {plan.version}",
        f"platform: {plan.platform}",
        f"python: {plan.python_executable}",
        f"source_root: {plan.source_root}",
        f"output_dir: {plan.output_dir}",
        f"artifact_name: {plan.artifact_name}",
        f"format: {plan.format}",
        "",
        "checks:",
    ]

    for check in plan.checks:
        status = "OK" if check.ok else "FAIL"
        lines.append(f"- [{status}] {check.name}: {check.detail}")
        if check.recommendation:
            lines.append(f"  recommendation: {check.recommendation}")

    lines.append("")
    lines.append("includes:")
    for item in plan.includes:
        lines.append(f"- {item}")

    lines.append("")
    lines.append("next_steps:")
    for item in plan.next_steps:
        lines.append(f"- {item}")

    return "\n".join(lines)


def _render_json(plan: PackagePlan) -> str:
    payload: dict[str, Any] = asdict(plan)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ironclaw-package",
        description="Prepare a packaging plan for IronClaw-Security.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="Optional override for the project source root.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional override for the package output directory.",
    )
    parser.add_argument(
        "--format",
        default="zip",
        help="Package format to target: zip, tar, or directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the package plan as JSON.",
    )
    args = parser.parse_args()

    plan = build_package_plan(
        source_root=args.source_root,
        output_dir=args.output_dir,
        package_format=str(args.format).strip().lower(),
    )

    if args.json:
        print(_render_json(plan))
    else:
        print(_render_text(plan))

    return 0 if all(check.ok for check in plan.checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
