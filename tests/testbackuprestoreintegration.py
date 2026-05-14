from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.services.backupservice import (
    BackupRotationPolicy,
    BackupService,
    BackupTarget,
    FilesystemSnapshotProvider,
)
from app.services.restoreservice import RestoreService, resolve_manifest_sidecar


def _utc_dt(
    year: int,
    month: int,
    day: int,
    hour: int = 0,
    minute: int = 0,
    second: int = 0,
) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=UTC)


def _build_backup_service(
    tmp_path: Path,
    *,
    source_path: Path,
    target_name: str = "runtime-metadata",
    now: datetime | None = None,
) -> BackupService:
    target = BackupTarget(
        name=target_name,
        kind="export",
        format="jsonl.gz",
        base_path=source_path,
        rotation_policy=BackupRotationPolicy(max_hourly=3, max_daily=2, max_weekly=1, max_monthly=1),
        encrypt_at_rest=False,
        checksum_required=True,
    )
    return BackupService(
        root_backup_dir=tmp_path / "backups",
        targets=[target],
        snapshot_provider=FilesystemSnapshotProvider(),
        now=now or _utc_dt(2026, 4, 27, 19, 15, 0),
    )


def test_end_to_end_backup_restore_round_trip_for_runtime_metadata(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime-source"
    source_dir.mkdir(parents=True)
    (source_dir / "state.json").write_text('{"status":"ok","version":1}', encoding="utf-8")
    (source_dir / "events.log").write_text("evt-001\nevt-002\n", encoding="utf-8")

    backup_service = _build_backup_service(
        tmp_path,
        source_path=source_dir,
        now=_utc_dt(2026, 4, 27, 19, 16, 0),
    )
    manifest = backup_service.run_export("runtime-metadata")
    manifest_path = resolve_manifest_sidecar(Path(manifest.backup_path))

    restore_root = tmp_path / "restore-target"
    restore_service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 17, 0))

    validation = restore_service.validate_manifest(manifest_path)
    result = restore_service.restore(manifest_path, restore_root)

    restored_file = restore_root / "runtime-metadata.restore.jsonl"

    assert validation.ok is True
    assert result.status == "applied"
    assert result.mode == "apply"
    assert result.validation.ok is True
    assert restored_file.exists()

    lines = [json.loads(line) for line in restored_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    restored_paths = {entry["path"] for entry in lines}
    assert "state.json" in restored_paths
    assert "events.log" in restored_paths


def test_end_to_end_dry_run_does_not_mutate_restore_root(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime-source"
    source_dir.mkdir(parents=True)
    (source_dir / "state.json").write_text('{"status":"ok"}', encoding="utf-8")

    backup_service = _build_backup_service(
        tmp_path,
        source_path=source_dir,
        now=_utc_dt(2026, 4, 27, 19, 18, 0),
    )
    manifest = backup_service.run_export("runtime-metadata")
    manifest_path = resolve_manifest_sidecar(Path(manifest.backup_path))

    restore_root = tmp_path / "restore-target"
    restore_service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 19, 0))
    result = restore_service.dry_run_restore(manifest_path, restore_root)

    assert result.status == "dry-run"
    assert result.details["applied"] is False
    assert result.replay_log
    assert not restore_root.exists()


def test_end_to_end_failover_rolls_back_to_checkpoint_on_restore_failure(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "runtime-source"
    source_dir.mkdir(parents=True)
    (source_dir / "state.json").write_text('{"status":"ok","version":1}', encoding="utf-8")

    backup_service = _build_backup_service(
        tmp_path,
        source_path=source_dir,
        now=_utc_dt(2026, 4, 27, 19, 20, 0),
    )
    manifest = backup_service.run_export("runtime-metadata")
    manifest_path = resolve_manifest_sidecar(Path(manifest.backup_path))

    restore_root = tmp_path / "restore-target"
    restore_root.mkdir(parents=True)
    (restore_root / "stable.txt").write_text("checkpoint-state", encoding="utf-8")

    class FailingExecutor:
        def restore(self, manifest, restore_root: Path, dry_run: bool):
            raise RuntimeError("simulated restore failure")

        def rollback(self, rollback_checkpoint: Path, restore_root: Path):
            for child in list(restore_root.iterdir()):
                if child.is_dir():
                    import shutil

                    shutil.rmtree(child)
                else:
                    child.unlink(missing_ok=True)
            for child in rollback_checkpoint.iterdir():
                destination = restore_root / child.name
                if child.is_dir():
                    import shutil

                    shutil.copytree(child, destination, dirs_exist_ok=True)
                else:
                    destination.write_bytes(child.read_bytes())
            return [{"action": "rollback-applied", "destination": str(restore_root)}]

    restore_service = RestoreService(
        executor=FailingExecutor(),
        now=_utc_dt(2026, 4, 27, 19, 21, 0),
    )
    result = restore_service.replay_with_rollback_safety(manifest_path, restore_root)

    assert result.status == "rolled-back"
    assert result.mode == "rollback"
    assert result.details["rollback_triggered"] is True
    assert "RuntimeError" in result.details["exception"]
    assert (restore_root / "stable.txt").exists()
    assert not (restore_root / "runtime-metadata.restore.jsonl").exists()


def test_end_to_end_backup_rotation_and_restore_validation_coexist(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "runtime-source"
    source_dir.mkdir(parents=True)
    (source_dir / "state.json").write_text('{"status":"ok"}', encoding="utf-8")

    backup_service = _build_backup_service(
        tmp_path,
        source_path=source_dir,
        now=_utc_dt(2026, 4, 27, 19, 22, 0),
    )

    manifests = [backup_service.run_export("runtime-metadata") for _ in range(3)]
    removed = backup_service.rotate("runtime-metadata")

    restore_service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 23, 0))
    latest_manifest_path = resolve_manifest_sidecar(Path(manifests[-1].backup_path))
    validation = restore_service.validate_manifest(latest_manifest_path)

    assert len(manifests) == 3
    assert isinstance(removed, list)
    assert validation.ok is True
