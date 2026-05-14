from __future__ import annotations

import gzip
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

from app.services.restoreservice import (
    RestoreService,
    resolve_manifest_sidecar,
)


def _utc_dt(
    year: int,
    month: int,
    day: int,
    hour: int = 0,
    minute: int = 0,
    second: int = 0,
) -> datetime:
    return datetime(year, month, day, hour, minute, second, tzinfo=UTC)


def _write_jsonl_backup(backup_path: Path, records: list[dict[str, object]]) -> None:
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(backup_path, "wt", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")


def _write_tar_backup(backup_path: Path, source_dir: Path) -> None:
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(backup_path, "w:gz") as tar:
        tar.add(source_dir, arcname=source_dir.name)


def _write_manifest(
    backup_path: Path,
    *,
    target_name: str,
    target_kind: str,
    backup_format: str,
    size_bytes: int | None = None,
    sha256: str | None = None,
) -> Path:
    manifest_path = resolve_manifest_sidecar(backup_path)
    payload = {
        "target_name": target_name,
        "target_kind": target_kind,
        "backup_format": backup_format,
        "backup_path": str(backup_path),
        "created_at": "2026-04-27T19:00:00Z",
        "size_bytes": size_bytes if size_bytes is not None else backup_path.stat().st_size,
        "sha256": sha256,
        "rotation_tier": "hourly",
        "encryption_applied": False,
        "meta": {
            "rotation_policy": {
                "max_hourly": 24,
                "max_daily": 7,
                "max_weekly": 4,
                "max_monthly": 12,
            }
        },
    }
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return manifest_path


def test_validate_manifest_passes_for_valid_jsonl_backup(tmp_path: Path) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [{"path": "state.json", "is_dir": False, "size": 14}],
    )

    from app.services.restoreservice import _sha256_file

    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
        sha256=_sha256_file(backup_path),
    )

    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 5, 0))
    result = service.validate_manifest(manifest_path)

    assert result.ok is True
    assert result.manifest.target_name == "runtime-metadata"
    assert any(check["name"] == "checksum-match" and check["ok"] is True for check in result.checks)


def test_validate_manifest_fails_for_checksum_mismatch(tmp_path: Path) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [{"path": "state.json", "is_dir": False, "size": 14}],
    )

    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
        sha256="bad-checksum",
    )

    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 6, 0))
    result = service.validate_manifest(manifest_path)

    assert result.ok is False
    assert result.failure_reason == "manifest validation failed"
    assert any(check["name"] == "checksum-match" and check["ok"] is False for check in result.checks)


def test_build_restore_plan_lists_expected_replay_actions_for_jsonl_backup(
    tmp_path: Path,
) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [
            {"path": "state.json", "is_dir": False, "size": 14},
            {"path": "events.json", "is_dir": False, "size": 32},
        ],
    )

    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
    )

    restore_root = tmp_path / "restore-root"
    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 7, 0))
    plan = service.build_restore_plan(manifest_path, restore_root, dry_run=True)

    assert plan.mode == "dry-run"
    assert plan.target_name == "runtime-metadata"
    assert plan.restore_root == str(restore_root)
    assert len(plan.planned_actions) == 2
    assert all(action["action"] == "replay-line" for action in plan.planned_actions)
    assert plan.rollback_checkpoint


def test_dry_run_restore_does_not_materialize_output(tmp_path: Path) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [{"path": "state.json", "is_dir": False, "size": 14}],
    )

    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
    )

    restore_root = tmp_path / "restore-root"
    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 8, 0))
    result = service.dry_run_restore(manifest_path, restore_root)

    assert result.status == "dry-run"
    assert result.mode == "dry-run"
    assert result.details["applied"] is False
    assert result.replay_log
    assert not restore_root.exists()


def test_restore_applies_jsonl_backup_and_creates_checkpoint(tmp_path: Path) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [{"path": "state.json", "is_dir": False, "size": 14}],
    )

    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
    )

    restore_root = tmp_path / "restore-root"
    restore_root.mkdir(parents=True)
    (restore_root / "preexisting.txt").write_text("checkpoint-me", encoding="utf-8")

    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 9, 0))
    result = service.restore(manifest_path, restore_root)

    restored_file = restore_root / "runtime-metadata.restore.jsonl"

    assert result.status == "applied"
    assert result.mode == "apply"
    assert result.details["applied"] is True
    assert result.rollback_checkpoint
    assert restored_file.exists()
    assert "state.json" in restored_file.read_text(encoding="utf-8")

    checkpoint_root = Path(result.rollback_checkpoint)
    assert checkpoint_root.exists()
    assert (checkpoint_root / "preexisting.txt").exists()


def test_replay_with_rollback_safety_aliases_restore_flow(tmp_path: Path) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [{"path": "state.json", "is_dir": False, "size": 14}],
    )

    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
    )

    restore_root = tmp_path / "restore-root"
    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 10, 0))
    result = service.replay_with_rollback_safety(manifest_path, restore_root)

    assert result.status == "applied"
    assert result.mode == "apply"
    assert result.replay_log


def test_restore_rolls_back_when_executor_restore_fails(tmp_path: Path) -> None:
    backup_path = tmp_path / "backups" / "runtime-metadata-hourly-20260427T190000Z.jsonl.gz"
    _write_jsonl_backup(
        backup_path,
        [{"path": "state.json", "is_dir": False, "size": 14}],
    )
    manifest_path = _write_manifest(
        backup_path,
        target_name="runtime-metadata",
        target_kind="export",
        backup_format="jsonl.gz",
    )

    restore_root = tmp_path / "restore-root"
    restore_root.mkdir(parents=True)
    (restore_root / "stable.txt").write_text("safe", encoding="utf-8")

    class FailingExecutor:
        def restore(self, manifest, restore_root: Path, dry_run: bool) -> list[dict[str, object]]:
            raise RuntimeError("restore failed")

        def rollback(self, rollback_checkpoint: Path, restore_root: Path) -> list[dict[str, object]]:
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
            return [{"action": "rollback-applied", "path": str(restore_root)}]

    service = RestoreService(executor=FailingExecutor(), now=_utc_dt(2026, 4, 27, 19, 11, 0))
    result = service.restore(manifest_path, restore_root)

    assert result.status == "rolled-back"
    assert result.mode == "rollback"
    assert result.details["rollback_triggered"] is True
    assert "RuntimeError" in result.details["exception"]
    assert (restore_root / "stable.txt").exists()
    assert not (restore_root / "runtime-metadata.restore.jsonl").exists()


def test_manual_rollback_restores_checkpoint_contents(tmp_path: Path) -> None:
    restore_root = tmp_path / "restore-root"
    restore_root.mkdir(parents=True)
    checkpoint_root = tmp_path / ".restore-checkpoint-restore-root-20260427T191200Z"
    checkpoint_root.mkdir(parents=True)

    (checkpoint_root / "stable.txt").write_text("from-checkpoint", encoding="utf-8")
    (restore_root / "changed.txt").write_text("to-be-removed", encoding="utf-8")

    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 12, 0))
    result = service.rollback(restore_root, checkpoint_root)

    assert result.status == "rolled-back"
    assert result.mode == "rollback"
    assert (restore_root / "stable.txt").exists()
    assert not (restore_root / "changed.txt").exists()
    assert result.replay_log


def test_restore_extracts_tar_backup(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "schema.sql").write_text("create table t(id int);", encoding="utf-8")

    backup_path = tmp_path / "backups" / "database-daily-20260427T000000Z.tar.gz"
    _write_tar_backup(backup_path, source_dir)
    manifest_path = _write_manifest(
        backup_path,
        target_name="database",
        target_kind="snapshot",
        backup_format="tar.gz",
    )

    restore_root = tmp_path / "restore-root"
    service = RestoreService(now=_utc_dt(2026, 4, 27, 19, 13, 0))
    result = service.restore(manifest_path, restore_root)

    assert result.status == "applied"
    assert any(action["action"] == "extract-member" for action in result.replay_log)
    assert (restore_root / "source" / "schema.sql").exists()
