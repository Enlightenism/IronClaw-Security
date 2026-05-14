from __future__ import annotations

import gzip
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.services.backupservice import (
    BackupRotationPolicy,
    BackupService,
    BackupTarget,
    FilesystemSnapshotProvider,
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


def _build_service(
    tmp_path: Path,
    *,
    target: BackupTarget,
    now: datetime | None = None,
) -> BackupService:
    return BackupService(
        root_backup_dir=tmp_path / "backups",
        targets=[target],
        snapshot_provider=FilesystemSnapshotProvider(),
        now=now or _utc_dt(2026, 4, 27, 13, 0, 0),
    )


def test_backup_service_lists_targets_as_json_safe_payloads(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime"
    source_dir.mkdir()
    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(),
    )
    service = _build_service(tmp_path, target=target)

    targets = service.list_targets()

    assert len(targets) == 1
    assert targets[0]["name"] == "runtime-metadata"
    assert targets[0]["kind"] == "export"
    assert targets[0]["format"] == "jsonl.gz"
    assert isinstance(targets[0]["rotation_policy"], dict)


def test_run_export_creates_manifest_and_checksum_verified_artifact(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime"
    source_dir.mkdir()
    (source_dir / "state.json").write_text('{"status":"ok"}', encoding="utf-8")

    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(max_hourly=3, max_daily=2, max_weekly=1, max_monthly=1),
        checksum_required=True,
        encrypt_at_rest=False,
    )
    service = _build_service(
        tmp_path,
        target=target,
        now=_utc_dt(2026, 4, 27, 13, 5, 0),
    )

    manifest = service.run_export("runtime-metadata")
    artifact_path = Path(manifest.backup_path)
    sidecar_path = artifact_path.with_suffix(artifact_path.suffix + ".manifest.json")

    assert artifact_path.exists()
    assert artifact_path.suffix == ".gz"
    assert sidecar_path.exists()
    assert manifest.target_name == "runtime-metadata"
    assert manifest.target_kind == "export"
    assert manifest.backup_format == "jsonl.gz"
    assert manifest.rotation_tier == "hourly"
    assert manifest.sha256
    assert manifest.size_bytes > 0
    assert service.verify(manifest) is True

    payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    assert payload["target_name"] == "runtime-metadata"
    assert payload["backup_format"] == "jsonl.gz"
    assert payload["sha256"] == manifest.sha256

    with gzip.open(artifact_path, "rt", encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    assert lines
    assert any(entry["path"] == "state.json" for entry in lines)


def test_run_snapshot_creates_tarball_for_directory_source(tmp_path: Path) -> None:
    source_dir = tmp_path / "database-source"
    source_dir.mkdir()
    (source_dir / "schema.sql").write_text("create table test(id int);", encoding="utf-8")
    nested = source_dir / "nested"
    nested.mkdir()
    (nested / "rows.txt").write_text("alpha\nbeta\n", encoding="utf-8")

    target = BackupTarget(
        name="database",
        kind="snapshot",
        format="tar.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(),
        checksum_required=True,
        encrypt_at_rest=True,
    )
    service = _build_service(
        tmp_path,
        target=target,
        now=_utc_dt(2026, 4, 27, 0, 0, 0),
    )

    manifest = service.run_snapshot("database")
    artifact_path = Path(manifest.backup_path)

    assert artifact_path.exists()
    assert artifact_path.name.endswith(".tar.gz")
    assert manifest.target_name == "database"
    assert manifest.target_kind == "snapshot"
    assert manifest.backup_format == "tar.gz"
    assert manifest.rotation_tier == "daily"
    assert manifest.encryption_applied is True
    assert service.verify(manifest) is True

    with tarfile.open(artifact_path, "r:gz") as tar:
        names = tar.getnames()
    assert any(name.endswith("schema.sql") for name in names)
    assert any(name.endswith("nested/rows.txt") for name in names)


def test_rotation_uses_weekly_tier_for_sunday_non_first_day(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime"
    source_dir.mkdir()
    (source_dir / "state.json").write_text("{}", encoding="utf-8")

    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(),
    )
    service = _build_service(
        tmp_path,
        target=target,
        now=_utc_dt(2026, 4, 26, 8, 0, 0),
    )

    manifest = service.run_export("runtime-metadata")
    assert manifest.rotation_tier == "weekly"


def test_rotation_uses_monthly_tier_on_first_day(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime"
    source_dir.mkdir()
    (source_dir / "state.json").write_text("{}", encoding="utf-8")

    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(),
    )
    service = _build_service(
        tmp_path,
        target=target,
        now=_utc_dt(2026, 5, 1, 8, 0, 0),
    )

    manifest = service.run_export("runtime-metadata")
    assert manifest.rotation_tier == "monthly"


def test_rotate_removes_backups_beyond_policy_limit(tmp_path: Path) -> None:
    target_root = tmp_path / "backups" / "runtime-metadata" / "hourly"
    target_root.mkdir(parents=True)

    for index in range(4):
        file_path = target_root / f"runtime-metadata-hourly-20260427T130{index}00Z.jsonl.gz"
        file_path.write_bytes(f"artifact-{index}".encode())

    source_dir = tmp_path / "runtime"
    source_dir.mkdir()

    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(max_hourly=2, max_daily=1, max_weekly=1, max_monthly=1),
    )
    service = _build_service(tmp_path, target=target)

    removed = service.rotate("runtime-metadata")
    remaining = sorted(path.name for path in target_root.glob("*") if path.is_file())

    assert len(removed) == 2
    assert len(remaining) == 2


def test_verify_returns_false_when_artifact_is_missing(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime"
    source_dir.mkdir()
    (source_dir / "state.json").write_text("{}", encoding="utf-8")

    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(),
    )
    service = _build_service(tmp_path, target=target)

    manifest = service.run_export("runtime-metadata")
    artifact_path = Path(manifest.backup_path)
    artifact_path.unlink()

    assert service.verify(manifest) is False


def test_run_snapshot_raises_for_unknown_target(tmp_path: Path) -> None:
    source_dir = tmp_path / "runtime"
    source_dir.mkdir()

    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=source_dir,
        rotation_policy=BackupRotationPolicy(),
    )
    service = _build_service(tmp_path, target=target)

    with pytest.raises(KeyError):
        service.run_snapshot("missing-target")


def test_run_export_raises_when_source_path_does_not_exist(tmp_path: Path) -> None:
    target = BackupTarget(
        name="runtime-metadata",
        kind="export",
        format="jsonl.gz",
        base_path=tmp_path / "missing-runtime",
        rotation_policy=BackupRotationPolicy(),
    )
    service = _build_service(tmp_path, target=target)

    with pytest.raises(FileNotFoundError):
        service.run_export("runtime-metadata")
