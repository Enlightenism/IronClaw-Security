from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import tarfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

RestoreMode = Literal["validate", "dry-run", "apply", "rollback"]
RestoreStatus = Literal["pending", "validated", "dry-run", "applied", "rolled-back", "failed"]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class RestoreManifest:
    target_name: str
    target_kind: str
    backup_format: str
    backup_path: str
    created_at: str
    size_bytes: int
    sha256: str | None
    rotation_tier: str
    encryption_applied: bool
    meta: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RestoreManifest:
        return cls(
            target_name=str(payload["target_name"]),
            target_kind=str(payload["target_kind"]),
            backup_format=str(payload["backup_format"]),
            backup_path=str(payload["backup_path"]),
            created_at=str(payload["created_at"]),
            size_bytes=int(payload["size_bytes"]),
            sha256=str(payload["sha256"]) if payload.get("sha256") else None,
            rotation_tier=str(payload["rotation_tier"]),
            encryption_applied=bool(payload.get("encryption_applied", False)),
            meta=dict(payload.get("meta") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RestoreValidationResult:
    ok: bool
    manifest: RestoreManifest
    checked_at: str
    checks: list[dict[str, Any]]
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RestorePlan:
    mode: RestoreMode
    target_name: str
    backup_path: str
    restore_root: str
    created_at: str
    planned_actions: list[dict[str, Any]]
    rollback_checkpoint: str | None
    validation: RestoreValidationResult

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RestoreResult:
    mode: RestoreMode
    status: RestoreStatus
    target_name: str
    backup_path: str
    restore_root: str
    started_at: str
    completed_at: str
    replay_log: list[dict[str, Any]]
    rollback_checkpoint: str | None
    validation: RestoreValidationResult
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class RestoreExecutor(Protocol):
    def restore(self, manifest: RestoreManifest, restore_root: Path, dry_run: bool) -> list[dict[str, Any]]:
        ...

    def rollback(self, rollback_checkpoint: Path, restore_root: Path) -> list[dict[str, Any]]:
        ...


class FilesystemRestoreExecutor:
    """
    Filesystem-oriented restore executor.

    - tar.gz: extracts archive to restore root
    - jsonl.gz: replays lines into a materialized jsonl file for inspection
    """

    def restore(
        self,
        manifest: RestoreManifest,
        restore_root: Path,
        dry_run: bool,
    ) -> list[dict[str, Any]]:
        backup_path = Path(manifest.backup_path)
        actions: list[dict[str, Any]] = []

        if manifest.backup_format == "tar.gz":
            with tarfile.open(backup_path, "r:gz") as tar:
                members = tar.getmembers()
                actions.extend(
                    {
                        "action": "extract-member",
                        "member": member.name,
                        "size": member.size,
                    }
                    for member in members
                )
                if not dry_run:
                    _ensure_dir(restore_root)
                    tar.extractall(path=restore_root)
            return actions

        if manifest.backup_format == "jsonl.gz":
            destination = restore_root / f"{manifest.target_name}.restore.jsonl"
            with gzip.open(backup_path, "rt", encoding="utf-8") as source:
                lines = source.readlines()
            actions.extend(
                {
                    "action": "replay-line",
                    "line_number": index + 1,
                }
                for index, _ in enumerate(lines)
            )
            if not dry_run:
                _ensure_dir(destination.parent)
                destination.write_text("".join(lines), encoding="utf-8")
            return actions

        raise ValueError(f"unsupported backup format: {manifest.backup_format}")

    def rollback(self, rollback_checkpoint: Path, restore_root: Path) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        if restore_root.exists():
            for child in sorted(restore_root.iterdir(), key=lambda item: item.name):
                actions.append({"action": "remove-restored-path", "path": str(child)})
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink(missing_ok=True)

        if rollback_checkpoint.exists():
            for child in sorted(rollback_checkpoint.iterdir(), key=lambda item: item.name):
                destination = restore_root / child.name
                actions.append(
                    {
                        "action": "restore-checkpoint-path",
                        "source": str(child),
                        "destination": str(destination),
                    }
                )
                if child.is_dir():
                    shutil.copytree(child, destination, dirs_exist_ok=True)
                else:
                    _ensure_dir(destination.parent)
                    shutil.copy2(child, destination)

        return actions


class RestoreService:
    """
    Owns validated restore, dry-run restore, and rollback-safe replay for IronClaw.

    Expected artifact layout:
    - backup artifact: /path/to/backup.tar.gz or /path/to/export.jsonl.gz
    - manifest sidecar: /path/to/backup.tar.gz.manifest.json
    """

    def __init__(
        self,
        executor: RestoreExecutor | None = None,
        now: datetime | None = None,
    ) -> None:
        self._executor = executor or FilesystemRestoreExecutor()
        self._now = now or _utc_now()

    # ------------------------------------------------------------------ #
    # Manifest loading and validation
    # ------------------------------------------------------------------ #

    def load_manifest(self, manifest_path: Path) -> RestoreManifest:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"invalid manifest payload: {manifest_path}")
        return RestoreManifest.from_dict(payload)

    def validate_manifest(self, manifest_path: Path) -> RestoreValidationResult:
        manifest = self.load_manifest(manifest_path)
        backup_path = Path(manifest.backup_path)

        checks: list[dict[str, Any]] = [
            {
                "name": "backup-path-exists",
                "ok": backup_path.exists(),
                "detail": str(backup_path),
            },
            {
                "name": "backup-path-is-file",
                "ok": backup_path.is_file(),
                "detail": str(backup_path),
            },
            {
                "name": "backup-format-supported",
                "ok": manifest.backup_format in {"tar.gz", "jsonl.gz"},
                "detail": manifest.backup_format,
            },
            {
                "name": "size-bytes-positive",
                "ok": manifest.size_bytes >= 0,
                "detail": manifest.size_bytes,
            },
        ]

        checksum_ok = True
        if manifest.sha256 and backup_path.exists() and backup_path.is_file():
            actual = _sha256_file(backup_path)
            checksum_ok = actual == manifest.sha256
            checks.append(
                {
                    "name": "checksum-match",
                    "ok": checksum_ok,
                    "detail": {"expected": manifest.sha256, "actual": actual},
                }
            )
        else:
            checks.append(
                {
                    "name": "checksum-match",
                    "ok": manifest.sha256 is None,
                    "detail": "skipped-no-checksum" if manifest.sha256 is None else "missing-backup-file",
                }
            )

        ok = all(bool(check["ok"]) for check in checks)
        failure_reason = None if ok else "manifest validation failed"

        return RestoreValidationResult(
            ok=ok,
            manifest=manifest,
            checked_at=_iso(self._now) or "",
            checks=checks,
            failure_reason=failure_reason,
        )

    # ------------------------------------------------------------------ #
    # Planning
    # ------------------------------------------------------------------ #

    def build_restore_plan(self, manifest_path: Path, restore_root: Path, dry_run: bool = True) -> RestorePlan:
        validation = self.validate_manifest(manifest_path)
        manifest = validation.manifest
        mode: RestoreMode = "dry-run" if dry_run else "apply"

        planned_actions = self._preview_actions(manifest, restore_root)
        rollback_checkpoint = str(self._checkpoint_path(restore_root))

        return RestorePlan(
            mode=mode,
            target_name=manifest.target_name,
            backup_path=manifest.backup_path,
            restore_root=str(restore_root),
            created_at=_iso(self._now) or "",
            planned_actions=planned_actions,
            rollback_checkpoint=rollback_checkpoint,
            validation=validation,
        )

    def _preview_actions(self, manifest: RestoreManifest, restore_root: Path) -> list[dict[str, Any]]:
        backup_path = Path(manifest.backup_path)

        if manifest.backup_format == "tar.gz":
            with tarfile.open(backup_path, "r:gz") as tar:
                return [
                    {
                        "action": "extract-member",
                        "member": member.name,
                        "size": member.size,
                        "restore_root": str(restore_root),
                    }
                    for member in tar.getmembers()
                ]

        if manifest.backup_format == "jsonl.gz":
            with gzip.open(backup_path, "rt", encoding="utf-8") as fh:
                return [
                    {
                        "action": "replay-line",
                        "line_number": index + 1,
                        "restore_root": str(restore_root),
                    }
                    for index, _ in enumerate(fh)
                ]

        raise ValueError(f"unsupported backup format: {manifest.backup_format}")

    # ------------------------------------------------------------------ #
    # Restore execution
    # ------------------------------------------------------------------ #

    def dry_run_restore(self, manifest_path: Path, restore_root: Path) -> RestoreResult:
        validation = self.validate_manifest(manifest_path)
        if not validation.ok:
            return self._failed_result(
                mode="dry-run",
                validation=validation,
                restore_root=restore_root,
                details={"reason": validation.failure_reason},
            )

        replay_log = self._executor.restore(validation.manifest, restore_root, dry_run=True)
        return RestoreResult(
            mode="dry-run",
            status="dry-run",
            target_name=validation.manifest.target_name,
            backup_path=validation.manifest.backup_path,
            restore_root=str(restore_root),
            started_at=_iso(self._now) or "",
            completed_at=_iso(_utc_now()) or "",
            replay_log=replay_log,
            rollback_checkpoint=None,
            validation=validation,
            details={"applied": False},
        )

    def restore(self, manifest_path: Path, restore_root: Path) -> RestoreResult:
        validation = self.validate_manifest(manifest_path)
        started_at = _iso(self._now) or ""

        if not validation.ok:
            return self._failed_result(
                mode="apply",
                validation=validation,
                restore_root=restore_root,
                details={"reason": validation.failure_reason},
            )

        checkpoint = self._create_rollback_checkpoint(restore_root)
        try:
            replay_log = self._executor.restore(validation.manifest, restore_root, dry_run=False)
            return RestoreResult(
                mode="apply",
                status="applied",
                target_name=validation.manifest.target_name,
                backup_path=validation.manifest.backup_path,
                restore_root=str(restore_root),
                started_at=started_at,
                completed_at=_iso(_utc_now()) or "",
                replay_log=replay_log,
                rollback_checkpoint=str(checkpoint),
                validation=validation,
                details={"applied": True},
            )
        except Exception as exc:
            rollback_log = self._executor.rollback(checkpoint, restore_root)
            return RestoreResult(
                mode="rollback",
                status="rolled-back",
                target_name=validation.manifest.target_name,
                backup_path=validation.manifest.backup_path,
                restore_root=str(restore_root),
                started_at=started_at,
                completed_at=_iso(_utc_now()) or "",
                replay_log=rollback_log,
                rollback_checkpoint=str(checkpoint),
                validation=validation,
                details={
                    "applied": False,
                    "exception": f"{type(exc).__name__}: {exc}",
                    "rollback_triggered": True,
                },
            )

    def replay_with_rollback_safety(self, manifest_path: Path, restore_root: Path) -> RestoreResult:
        """
        Higher-level helper for explicit rollback-safe replay.
        Equivalent to restore(), but named for orchestration clarity.
        """
        return self.restore(manifest_path, restore_root)

    def rollback(self, restore_root: Path, rollback_checkpoint: Path) -> RestoreResult:
        manifest = RestoreManifest(
            target_name="rollback",
            target_kind="rollback",
            backup_format="rollback",
            backup_path=str(rollback_checkpoint),
            created_at=_iso(self._now) or "",
            size_bytes=0,
            sha256=None,
            rotation_tier="rollback",
            encryption_applied=False,
            meta={},
        )
        validation = RestoreValidationResult(
            ok=True,
            manifest=manifest,
            checked_at=_iso(self._now) or "",
            checks=[
                {
                    "name": "rollback-checkpoint-exists",
                    "ok": rollback_checkpoint.exists(),
                    "detail": str(rollback_checkpoint),
                }
            ],
            failure_reason=None,
        )

        replay_log = self._executor.rollback(rollback_checkpoint, restore_root)
        return RestoreResult(
            mode="rollback",
            status="rolled-back",
            target_name=manifest.target_name,
            backup_path=manifest.backup_path,
            restore_root=str(restore_root),
            started_at=_iso(self._now) or "",
            completed_at=_iso(_utc_now()) or "",
            replay_log=replay_log,
            rollback_checkpoint=str(rollback_checkpoint),
            validation=validation,
            details={"applied": False, "rollback_triggered": True},
        )

    # ------------------------------------------------------------------ #
    # Rollback checkpointing
    # ------------------------------------------------------------------ #

    def _checkpoint_path(self, restore_root: Path) -> Path:
        timestamp = self._now.strftime("%Y%m%dT%H%M%SZ")
        return restore_root.parent / f".restore-checkpoint-{restore_root.name}-{timestamp}"

    def _create_rollback_checkpoint(self, restore_root: Path) -> Path:
        checkpoint = self._checkpoint_path(restore_root)
        if checkpoint.exists():
            shutil.rmtree(checkpoint)

        _ensure_dir(checkpoint)

        if restore_root.exists():
            for child in restore_root.iterdir():
                destination = checkpoint / child.name
                if child.is_dir():
                    shutil.copytree(child, destination, dirs_exist_ok=True)
                else:
                    _ensure_dir(destination.parent)
                    shutil.copy2(child, destination)

        return checkpoint

    # ------------------------------------------------------------------ #
    # Result helpers
    # ------------------------------------------------------------------ #

    def _failed_result(
        self,
        *,
        mode: RestoreMode,
        validation: RestoreValidationResult,
        restore_root: Path,
        details: dict[str, Any] | None = None,
    ) -> RestoreResult:
        return RestoreResult(
            mode=mode,
            status="failed",
            target_name=validation.manifest.target_name,
            backup_path=validation.manifest.backup_path,
            restore_root=str(restore_root),
            started_at=_iso(self._now) or "",
            completed_at=_iso(_utc_now()) or "",
            replay_log=[],
            rollback_checkpoint=None,
            validation=validation,
            details=details or {},
        )


def resolve_manifest_sidecar(backup_path: Path) -> Path:
    return backup_path.with_name(f"{backup_path.name}.manifest.json")