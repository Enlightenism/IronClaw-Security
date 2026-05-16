from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
CHANGELOG_FILE = ROOT / "CHANGELOG.md"
MIGRATIONS_DIR = ROOT / "migrations"
UPDATE_STATE_FILE = ROOT / ".update-state.json"
ROLLBACK_NOTES_FILE = ROOT / "ROLLBACK_NOTES.md"
VERIFY_SCRIPT = ROOT / "scripts" / "verify.py"

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _print(msg: str) -> None:
    print(msg)


def _fail(msg: str, exit_code: int = 1) -> None:
    _print(f"ERROR: {msg}")
    raise SystemExit(exit_code)


def _run(cmd: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd or ROOT), check=True)


def _read_text(path: Path) -> str:
    if not path.exists():
        _fail(f"required file is missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8").strip()


def _load_state() -> dict[str, Any]:
    if not UPDATE_STATE_FILE.exists():
        return {}
    try:
        return json.loads(UPDATE_STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"invalid update state file: {exc}")
        return {}


def _save_state(state: dict[str, Any]) -> None:
    state["updated_at"] = datetime.now(UTC).isoformat()
    UPDATE_STATE_FILE.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _read_version() -> str:
    version = _read_text(VERSION_FILE)
    if not SEMVER_RE.match(version):
        _fail("VERSION must use semantic version format like 1.2.3")
    return version


def _parse_semver(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def _ensure_version_progression(previous: str | None, current: str) -> None:
    if previous is None:
        _print(f"Initial update state created at version {current}")
        return
    if _parse_semver(current) < _parse_semver(previous):
        _fail(f"version regression detected: previous={previous}, current={current}")
    if _parse_semver(current) == _parse_semver(previous):
        _print(f"Version unchanged at {current}; update remains idempotent")
    else:
        _print(f"Version update detected: {previous} -> {current}")


def _ensure_changelog_mentions(version: str) -> None:
    changelog = _read_text(CHANGELOG_FILE)
    if version not in changelog:
        _fail(f"CHANGELOG.md does not mention current version {version}")
    _print("Changelog check passed")


def _discover_migrations() -> list[str]:
    if not MIGRATIONS_DIR.exists():
        _print("No migrations directory found; skipping migration hooks")
        return []
    files = sorted(path.name for path in MIGRATIONS_DIR.iterdir() if path.is_file() and path.suffix.lower() in {".sql", ".py"})
    _print(f"Discovered {len(files)} migration file(s)")
    return files


def _record_migration_hooks(state: dict[str, Any], migrations: list[str]) -> None:
    state["migration_hooks"] = migrations
    state["migration_hook_status"] = "detected" if migrations else "none"


def _ensure_rollback_notes(version: str) -> None:
    if not ROLLBACK_NOTES_FILE.exists():
        ROLLBACK_NOTES_FILE.write_text(
            "\n".join(
                [
                    "# Rollback Notes",
                    "",
                    f"## Current version: {version}",
                    "",
                    "- Revert application code to the previous known-good release.",
                    "- Reinstall pinned dependencies if requirements changed.",
                    "- Restore database from backup before reverting incompatible migrations.",
                    "- Re-run verification after rollback.",
                    "",
                ],
            )
            + "\n",
            encoding="utf-8",
        )
        _print("Created ROLLBACK_NOTES.md")
        return

    existing = ROLLBACK_NOTES_FILE.read_text(encoding="utf-8")
    if version not in existing:
        with ROLLBACK_NOTES_FILE.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n## Reviewed for version: {version}\n- Confirm previous deployment artifact is available.\n- Confirm database rollback or restore path is documented.\n- Confirm post-rollback verification command is ready.\n",
            )
        _print("Appended version-specific rollback notes")
    else:
        _print("Rollback notes already cover current version")


def _run_migration_hook_if_present() -> None:
    hook = ROOT / "scripts" / "apply_migrations.py"
    if not hook.exists():
        _print("No apply_migrations.py hook found; skipping migration execution hook")
        return
    _print("Running migration hook")
    _run([sys.executable, str(hook)])


def _run_verify_if_present() -> None:
    if not VERIFY_SCRIPT.exists():
        _print("No scripts/verify.py found; skipping post-update verify hook")
        return
    _print("Running post-update verification")
    _run([sys.executable, str(VERIFY_SCRIPT)])


def main() -> None:
    try:
        current_version = _read_version()
        state = _load_state()
        previous_version = state.get("last_version")

        _ensure_version_progression(previous_version, current_version)
        _ensure_changelog_mentions(current_version)

        migrations = _discover_migrations()
        _record_migration_hooks(state, migrations)

        _run_migration_hook_if_present()
        _ensure_rollback_notes(current_version)
        _run_verify_if_present()

        state["last_version"] = current_version
        state["status"] = "ok"
        _save_state(state)

        _print("Update completed successfully")
    except subprocess.CalledProcessError as exc:
        _fail(f"command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}")


if __name__ == "__main__":
    main()
