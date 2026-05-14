from __future__ import annotations

import argparse
import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUPABASE_MIGRATIONS = REPO_ROOT / "supabase" / "migrations"
DEFAULT_RUNTIME_OUTPUT = REPO_ROOT / "output"
DEFAULT_BACKUP_DIR = REPO_ROOT / "backups"
ENV_FILES = (".env", ".env.example")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _safe_listdir(path: Path) -> list[Path]:
    if not path.exists() or not path.is_dir():
        return []
    return sorted(path.iterdir(), key=lambda item: item.name.lower())


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in _read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _load_env_values() -> dict[str, str]:
    merged: dict[str, str] = {}
    for filename in ENV_FILES:
        merged.update(_parse_env_file(REPO_ROOT / filename))
    merged.update({key: value for key, value in os.environ.items() if value is not None})
    return merged


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, int | float):
        return bool(value)
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _contains_any(text: str, needles: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    name: str
    status: str
    summary: str
    details: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "details": list(self.details),
            "remediation": list(self.remediation),
        }


@dataclass(frozen=True, slots=True)
class BackupRestoreTargets:
    backup_directory: str
    restore_directory: str
    retention_days: int
    encryption_expected: bool
    checksum_expected: bool
    rollback_expected: bool
    runbook_expected: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DeploymentReadinessReport:
    generated_at: str
    overall_status: str
    score: int
    checks: tuple[ReadinessCheck, ...] = ()
    targets: BackupRestoreTargets | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall_status": self.overall_status,
            "score": self.score,
            "checks": [item.to_dict() for item in self.checks],
            "targets": self.targets.to_dict() if self.targets else None,
        }


@dataclass(slots=True)
class DeploymentReadinessEvaluator:
    repo_root: Path = field(default=REPO_ROOT)
    env: dict[str, str] = field(default_factory=_load_env_values)

    def evaluate(self) -> DeploymentReadinessReport:
        checks = (
            self._check_backup_targets(),
            self._check_restore_targets(),
            self._check_supabase_migrations(),
            self._check_runtime_outputs(),
            self._check_backup_runbook_markers(),
            self._check_env_configuration(),
        )
        score = self._calculate_score(checks)
        return DeploymentReadinessReport(
            generated_at=_isoformat(_utc_now()) or "",
            overall_status=self._overall_status(checks),
            score=score,
            checks=checks,
            targets=self._backup_restore_targets(),
        )

    def _backup_restore_targets(self) -> BackupRestoreTargets:
        retention_days = self._env_int("IRONCLAW_BACKUP_RETENTION_DAYS", 30)
        return BackupRestoreTargets(
            backup_directory=str((self.repo_root / "backups").resolve()),
            restore_directory=str((self.repo_root / "output").resolve()),
            retention_days=max(1, retention_days),
            encryption_expected=True,
            checksum_expected=True,
            rollback_expected=True,
            runbook_expected=True,
        )

    def _check_backup_targets(self) -> ReadinessCheck:
        backup_dir = self.repo_root / "backups"
        scripts_dir = self.repo_root / "scripts"
        candidates = [
            backup_dir.exists(),
            any("backup" in item.name.lower() for item in _safe_listdir(scripts_dir)),
            any("backup" in item.name.lower() for item in _safe_listdir(self.repo_root)),
        ]
        configured = any(candidates)

        details = [
            f"Backup directory path: {backup_dir}",
            f"Backup directory exists: {backup_dir.exists()}",
            f"Backup-related script marker found: {candidates[1] or candidates[2]}",
        ]
        remediation = (
            "Create a dedicated backups/ directory under the repository root.",
            "Add an automated backup script that exports persistence state and audit evidence.",
            "Store backup metadata with immutable timestamps and integrity checksums.",
        )

        return ReadinessCheck(
            name="backup_targets",
            status="pass" if configured else "warn",
            summary="Backup target structure is present." if configured else "Backup target structure is not fully defined.",
            details=tuple(details),
            remediation=() if configured else remediation,
        )

    def _check_restore_targets(self) -> ReadinessCheck:
        output_dir = self.repo_root / "output"
        restore_signals = [
            output_dir.exists(),
            (self.repo_root / "scripts" / "deploymentreadiness.py").exists(),
            any("restore" in item.name.lower() for item in _safe_listdir(self.repo_root / "scripts")),
        ]
        details = [
            f"Restore output path: {output_dir}",
            f"Output directory exists: {output_dir.exists()}",
            f"Restore-specific script marker found: {restore_signals[2]}",
        ]
        remediation = (
            "Add a restore workflow script that validates backup manifests before import.",
            "Implement dry-run restore validation for rollback safety.",
            "Persist restore audit events to the audit log path.",
        )

        ready = restore_signals[0] and restore_signals[1]
        return ReadinessCheck(
            name="restore_targets",
            status="pass" if ready else "warn",
            summary="Restore target path is available." if ready else "Restore targets need explicit automation.",
            details=tuple(details),
            remediation=() if ready else remediation,
        )

    def _check_supabase_migrations(self) -> ReadinessCheck:
        migrations_dir = DEFAULT_SUPABASE_MIGRATIONS
        files = [item for item in _safe_listdir(migrations_dir) if item.suffix.lower() == ".sql"]
        has_schema = len(files) >= 3
        details = [
            f"Migrations directory: {migrations_dir}",
            f"SQL migration count: {len(files)}",
            f"Latest migration: {files[-1].name if files else 'none'}",
        ]
        remediation = (
            "Add schema coverage for backup manifests, restore jobs, and retention ledger tables.",
            "Ensure migrations are idempotent and ordered for disaster recovery replay.",
        )
        return ReadinessCheck(
            name="supabase_migrations",
            status="pass" if has_schema else "fail",
            summary="Migration baseline is present." if has_schema else "Migration baseline is insufficient for recovery readiness.",
            details=tuple(details),
            remediation=() if has_schema else remediation,
        )

    def _check_runtime_outputs(self) -> ReadinessCheck:
        output_dir = DEFAULT_RUNTIME_OUTPUT
        files = [item for item in _safe_listdir(output_dir) if item.is_file()]
        has_artifacts = len(files) > 0
        details = [
            f"Runtime output directory: {output_dir}",
            f"Artifact count: {len(files)}",
            f"Sample artifacts: {', '.join(item.name for item in files[:5]) if files else 'none'}",
        ]
        remediation = (
            "Emit backup manifests and restore verification reports into output/ for operator review.",
            "Generate signed checksum files for exported runtime artifacts.",
        )
        return ReadinessCheck(
            name="runtime_outputs",
            status="pass" if has_artifacts else "warn",
            summary="Runtime output artifacts are available." if has_artifacts else "No runtime artifacts found for backup verification.",
            details=tuple(details),
            remediation=() if has_artifacts else remediation,
        )

    def _check_backup_runbook_markers(self) -> ReadinessCheck:
        candidate_files = [
            self.repo_root / "README.md",
            self.repo_root / "ROLLBACK_NOTES.md",
            self.repo_root / "docs" / "backup-restore.md",
        ]
        scanned: list[str] = []
        found_keywords = False
        for path in candidate_files:
            if not path.exists():
                continue
            content = _read_text(path)
            scanned.append(path.name)
            if _contains_any(content, ("backup", "restore", "rollback", "recovery")):
                found_keywords = True

        details = [
            f"Scanned runbook sources: {', '.join(scanned) if scanned else 'none'}",
            f"Recovery keywords detected: {found_keywords}",
        ]
        remediation = (
            "Document backup cadence, retention, restore steps, checksum verification, and rollback ownership.",
            "Add operator runbook steps for backup failure escalation and restore validation.",
        )
        return ReadinessCheck(
            name="runbook_markers",
            status="pass" if found_keywords else "warn",
            summary="Recovery runbook markers detected." if found_keywords else "Recovery runbook content is not explicit yet.",
            details=tuple(details),
            remediation=() if found_keywords else remediation,
        )

    def _check_env_configuration(self) -> ReadinessCheck:
        required = {
            "SUPABASE_URL": bool(self.env.get("SUPABASE_URL")),
            "SUPABASE_SERVICE_ROLE_KEY": bool(self.env.get("SUPABASE_SERVICE_ROLE_KEY")),
        }
        optional_recovery = {
            "IRONCLAW_BACKUP_RETENTION_DAYS": bool(self.env.get("IRONCLAW_BACKUP_RETENTION_DAYS")),
            "IRONCLAW_BACKUP_ENCRYPTION": bool(self.env.get("IRONCLAW_BACKUP_ENCRYPTION")),
            "IRONCLAW_BACKUP_CHECKSUM": bool(self.env.get("IRONCLAW_BACKUP_CHECKSUM")),
        }
        missing_required = [key for key, present in required.items() if not present]
        configured_optional = [key for key, present in optional_recovery.items() if present]

        if missing_required:
            status = "fail"
        elif configured_optional:
            status = "pass"
        else:
            status = "warn"

        details = [
            f"Required env configured: {', '.join(key for key, present in required.items() if present) or 'none'}",
            f"Missing required env: {', '.join(missing_required) or 'none'}",
            f"Recovery env configured: {', '.join(configured_optional) or 'none'}",
        ]
        remediation = (
            "Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY using secure secret management.",
            "Define backup retention, encryption, and checksum environment variables.",
            "Fail deployment readiness in production when recovery configuration is absent.",
        )
        return ReadinessCheck(
            name="environment_configuration",
            status=status,
            summary="Environment baseline is fully configured." if status == "pass" else "Environment baseline is incomplete.",
            details=tuple(details),
            remediation=() if status == "pass" else remediation,
        )

    def _env_int(self, key: str, default: int) -> int:
        value = self.env.get(key)
        try:
            return int(str(value).strip()) if value is not None else default
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _calculate_score(checks: tuple[ReadinessCheck, ...]) -> int:
        weights = {"pass": 100, "warn": 60, "fail": 0}
        if not checks:
            return 0
        total = sum(weights.get(item.status, 0) for item in checks)
        return round(total / len(checks))

    @staticmethod
    def _overall_status(checks: tuple[ReadinessCheck, ...]) -> str:
        statuses = {item.status for item in checks}
        if "fail" in statuses:
            return "fail"
        if "warn" in statuses:
            return "warn"
        return "pass"


def _print_human_report(report: DeploymentReadinessReport) -> None:
    print(f"IronClaw deployment readiness: {report.overall_status.upper()} ({report.score})")
    print(f"Generated at: {report.generated_at}")
    print()
    for check in report.checks:
        print(f"[{check.status.upper()}] {check.name}: {check.summary}")
        for detail in check.details:
            print(f"  - {detail}")
        if check.remediation:
            for item in check.remediation:
                print(f"  * {item}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate IronClaw deployment readiness targets for backup and restore implementation.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the readiness report as JSON.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero exit code unless overall readiness is pass.",
    )
    args = parser.parse_args(argv)

    evaluator = DeploymentReadinessEvaluator()
    report = evaluator.evaluate()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_human_report(report)

    if args.strict and report.overall_status != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
