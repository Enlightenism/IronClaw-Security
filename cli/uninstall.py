from __future__ import annotations

import argparse
import json
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class UninstallCheck:
    name: str
    ok: bool
    detail: str
    recommendation: str | None = None


@dataclass(slots=True)
class UninstallTarget:
    label: str
    path: str
    exists: bool
    removable: bool


@dataclass(slots=True)
class UninstallPlan:
    product: str
    version: str
    dry_run: bool
    purge_data: bool
    install_root: str
    config_root: str
    data_root: str
    targets: list[UninstallTarget]
    checks: list[UninstallCheck]
    next_steps: list[str]


def _default_install_root() -> Path:
    return Path.cwd()


def _default_config_root() -> Path:
    return Path.home() / ".ironclaw-security"


def _default_data_root() -> Path:
    return Path.home() / ".ironclaw-security-data"


def _path_state(path: Path) -> tuple[bool, bool]:
    exists = path.exists()
    removable = exists and path != path.anchor and path != Path.home()
    return exists, removable


def _build_targets(install_root: Path, config_root: Path, data_root: Path, purge_data: bool) -> list[UninstallTarget]:
    targets: list[UninstallTarget] = []

    for label, path in [
        ("install-root", install_root),
        ("config-root", config_root),
    ]:
        exists, removable = _path_state(path)
        targets.append(
            UninstallTarget(
                label=label,
                path=str(path),
                exists=exists,
                removable=removable,
            ),
        )

    if purge_data:
        exists, removable = _path_state(data_root)
        targets.append(
            UninstallTarget(
                label="data-root",
                path=str(data_root),
                exists=exists,
                removable=removable,
            ),
        )

    return targets


def _build_checks(targets: list[UninstallTarget]) -> list[UninstallCheck]:
    checks: list[UninstallCheck] = []

    if not targets:
        checks.append(
            UninstallCheck(
                name="targets",
                ok=False,
                detail="No uninstall targets were generated.",
                recommendation="Provide at least one valid uninstall target.",
            ),
        )
        return checks

    checks.append(
        UninstallCheck(
            name="target-count",
            ok=True,
            detail=f"Prepared {len(targets)} uninstall target(s).",
            recommendation=None,
        ),
    )

    for target in targets:
        if not target.exists:
            checks.append(
                UninstallCheck(
                    name=f"{target.label}-exists",
                    ok=True,
                    detail=f"Target not present, nothing to remove: {target.path}",
                    recommendation=None,
                ),
            )
        else:
            checks.append(
                UninstallCheck(
                    name=f"{target.label}-removable",
                    ok=target.removable,
                    detail=f"Target path: {target.path}",
                    recommendation=None if target.removable else "Refuse uninstall for unsafe root-level paths.",
                ),
            )

    return checks


def build_uninstall_plan(
    install_root: Path | None = None,
    config_root: Path | None = None,
    data_root: Path | None = None,
    purge_data: bool = False,
    dry_run: bool = True,
) -> UninstallPlan:
    resolved_install_root = (install_root or _default_install_root()).resolve()
    resolved_config_root = (config_root or _default_config_root()).resolve()
    resolved_data_root = (data_root or _default_data_root()).resolve()

    targets = _build_targets(
        install_root=resolved_install_root,
        config_root=resolved_config_root,
        data_root=resolved_data_root,
        purge_data=purge_data,
    )
    checks = _build_checks(targets)

    next_steps = [
        "Review uninstall targets before removing files.",
        "Run without --dry-run only after confirming the paths are correct.",
        "Use --purge-data only when you intend to remove stored runtime data.",
        "Run verify after reinstalling to confirm a clean recovery path.",
    ]

    return UninstallPlan(
        product="IronClaw-Security",
        version="gen1",
        dry_run=dry_run,
        purge_data=purge_data,
        install_root=str(resolved_install_root),
        config_root=str(resolved_config_root),
        data_root=str(resolved_data_root),
        targets=targets,
        checks=checks,
        next_steps=next_steps,
    )


def _remove_target(path: Path) -> None:
    if not path.exists():
        return
    if path.is_file() or path.is_symlink():
        path.unlink(missing_ok=True)
        return
    shutil.rmtree(path)


def run_uninstall_command(
    install_root: Path | None = None,
    config_root: Path | None = None,
    data_root: Path | None = None,
    purge_data: bool = False,
    dry_run: bool = True,
) -> UninstallPlan:
    plan = build_uninstall_plan(
        install_root=install_root,
        config_root=config_root,
        data_root=data_root,
        purge_data=purge_data,
        dry_run=dry_run,
    )

    if not all(check.ok for check in plan.checks):
        return plan

    if dry_run:
        return plan

    for target in plan.targets:
        if target.exists and target.removable:
            _remove_target(Path(target.path))

    return build_uninstall_plan(
        install_root=Path(plan.install_root),
        config_root=Path(plan.config_root),
        data_root=Path(plan.data_root),
        purge_data=purge_data,
        dry_run=dry_run,
    )


def _render_text(plan: UninstallPlan) -> str:
    lines = [
        f"{plan.product} uninstall plan",
        f"version: {plan.version}",
        f"dry_run: {str(plan.dry_run).lower()}",
        f"purge_data: {str(plan.purge_data).lower()}",
        f"install_root: {plan.install_root}",
        f"config_root: {plan.config_root}",
        f"data_root: {plan.data_root}",
        "",
        "targets:",
    ]

    for target in plan.targets:
        lines.append(
            f"- {target.label}: path={target.path}, exists={str(target.exists).lower()}, removable={str(target.removable).lower()}",
        )

    lines.append("")
    lines.append("checks:")
    for check in plan.checks:
        status = "OK" if check.ok else "FAIL"
        lines.append(f"- [{status}] {check.name}: {check.detail}")
        if check.recommendation:
            lines.append(f"  recommendation: {check.recommendation}")

    lines.append("")
    lines.append("next_steps:")
    for item in plan.next_steps:
        lines.append(f"- {item}")

    return "\n".join(lines)


def _render_json(plan: UninstallPlan) -> str:
    payload: dict[str, Any] = asdict(plan)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_uninstall_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw-uninstall",
        description="Remove an IronClaw-Security installation and optional local data.",
    )
    parser.add_argument(
        "--install-root",
        type=Path,
        default=None,
        help="Optional override for the installed project root.",
    )
    parser.add_argument(
        "--config-root",
        type=Path,
        default=None,
        help="Optional override for the user configuration directory.",
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=None,
        help="Optional override for the runtime data directory.",
    )
    parser.add_argument(
        "--purge-data",
        action="store_true",
        help="Also remove the runtime data directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be removed without deleting anything.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the uninstall result as JSON.",
    )
    return parser


def handle_uninstall_args(args: argparse.Namespace) -> int:
    plan = run_uninstall_command(
        install_root=args.install_root,
        config_root=args.config_root,
        data_root=args.data_root,
        purge_data=bool(args.purge_data),
        dry_run=bool(args.dry_run),
    )

    if args.json:
        print(_render_json(plan))
    else:
        print(_render_text(plan))

    return 0 if all(check.ok for check in plan.checks) else 1


def main() -> int:
    parser = build_uninstall_parser()
    args = parser.parse_args()

    if not args.dry_run and "--dry-run" not in sys.argv:
        args.dry_run = False

    return handle_uninstall_args(args)


if __name__ == "__main__":
    raise SystemExit(main())
