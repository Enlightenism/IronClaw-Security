from __future__ import annotations

from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.services.backupservice import (
    BackupFormat,
    BackupKind,
    BackupManifest,
    BackupRotationPolicy,
    BackupService,
    BackupTarget,
    FilesystemSnapshotProvider,
    RotationTier,
    SnapshotProvider,
    build_default_backup_service,
    default_backup_targets_from_env,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_policy(**overrides: int) -> BackupRotationPolicy:
    defaults = dict(max_hourly=24, max_daily=7, max_weekly=4, max_monthly=12)
    defaults.update(overrides)
    return BackupRotationPolicy(**defaults)


def _make_target(
    tmp_path: Path,
    name: str = "test-store",
    kind: BackupKind = "snapshot",
    fmt: BackupFormat = "tar.gz",
    encrypt: bool = True,
    checksum: bool = True,
    policy: BackupRotationPolicy | None = None,
) -> BackupTarget:
    source = tmp_path / "source" / name
    source.mkdir(parents=True, exist_ok=True)
    (source / "data.txt").write_text("ironclaw-backup-test", encoding="utf-8")
    return BackupTarget(
        name=name,
        kind=kind,
        format=fmt,
        base_path=source,
        rotation_policy=policy or _make_policy(),
        encrypt_at_rest=encrypt,
        checksum_required=checksum,
    )


def _make_service(tmp_path: Path, targets: list[BackupTarget]) -> BackupService:
    root = tmp_path / "backups"
    root.mkdir(parents=True, exist_ok=True)
    return BackupService(root_backup_dir=root, targets=targets)


def _make_manifest(
    tmp_path: Path,
    target: BackupTarget,
    tier: RotationTier = "hourly",
    sha: str | None = "abc123",
    size: int = 128,
) -> BackupManifest:
    artifact = tmp_path / "backups" / target.name / tier / "artifact.tar.gz"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"x" * size)
    real_sha = hashlib.sha256(b"x" * size).hexdigest()
    return BackupManifest(
        target_name=target.name,
        target_kind=target.kind,
        backup_format=target.format,
        backup_path=str(artifact),
        created_at="2026-05-18T00:00:00Z",
        size_bytes=size,
        sha256=real_sha if sha == "real" else sha,
        rotation_tier=tier,
        encryption_applied=target.encrypt_at_rest,
        meta={"rotation_policy": target.rotation_policy.to_dict()},
    )


# ---------------------------------------------------------------------------
# BackupRotationPolicy
# ---------------------------------------------------------------------------


class TestBackupRotationPolicy:
    def test_defaults(self) -> None:
        p = BackupRotationPolicy()
        assert p.max_hourly == 24
        assert p.max_daily == 7
        assert p.max_weekly == 4
        assert p.max_monthly == 12

    def test_custom_values(self) -> None:
        p = BackupRotationPolicy(max_hourly=6, max_daily=3, max_weekly=2, max_monthly=1)
        assert p.max_hourly == 6
        assert p.max_daily == 3
        assert p.max_weekly == 2
        assert p.max_monthly == 1

    def test_to_dict_keys(self) -> None:
        p = _make_policy()
        d = p.to_dict()
        assert set(d) == {"max_hourly", "max_daily", "max_weekly", "max_monthly"}

    def test_to_dict_values(self) -> None:
        p = BackupRotationPolicy(max_hourly=2, max_daily=3, max_weekly=4, max_monthly=5)
        d = p.to_dict()
        assert d["max_hourly"] == 2
        assert d["max_monthly"] == 5

    def test_frozen(self) -> None:
        p = BackupRotationPolicy()
        with pytest.raises((AttributeError, TypeError)):
            p.max_hourly = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# BackupTarget
# ---------------------------------------------------------------------------


class TestBackupTarget:
    def test_to_dict_base_path_is_string(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        d = t.to_dict()
        assert isinstance(d["base_path"], str)

    def test_to_dict_contains_rotation_policy(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        d = t.to_dict()
        assert "rotation_policy" in d

    def test_to_dict_name(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, name="db-store")
        assert t.to_dict()["name"] == "db-store"

    def test_frozen(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        with pytest.raises((AttributeError, TypeError)):
            t.name = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# BackupManifest
# ---------------------------------------------------------------------------


class TestBackupManifest:
    def test_to_dict_all_fields(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path)
        m = _make_manifest(tmp_path, target)
        d = m.to_dict()
        required = {
            "target_name",
            "target_kind",
            "backup_format",
            "backup_path",
            "created_at",
            "size_bytes",
            "sha256",
            "rotation_tier",
            "encryption_applied",
            "meta",
        }
        assert required.issubset(set(d))

    def test_target_name_preserved(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path, name="audit-store")
        m = _make_manifest(tmp_path, target)
        assert m.to_dict()["target_name"] == "audit-store"

    def test_rotation_tier_preserved(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path)
        m = _make_manifest(tmp_path, target, tier="daily")
        assert m.to_dict()["rotation_tier"] == "daily"


# ---------------------------------------------------------------------------
# SnapshotProvider protocol
# ---------------------------------------------------------------------------


class TestSnapshotProviderProtocol:
    def test_filesystem_provider_implements_protocol(self) -> None:
        provider = FilesystemSnapshotProvider()
        assert isinstance(provider, SnapshotProvider)

    def test_mock_provider_implements_protocol(self) -> None:
        mock = MagicMock(spec=SnapshotProvider)
        assert isinstance(mock, SnapshotProvider)


# ---------------------------------------------------------------------------
# FilesystemSnapshotProvider
# ---------------------------------------------------------------------------


class TestFilesystemSnapshotProvider:
    def test_snapshot_tar_gz_creates_file(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path, fmt="tar.gz")
        dest = tmp_path / "backups" / "test-store" / "hourly" / "snap.tar.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        provider = FilesystemSnapshotProvider()
        result = provider.snapshot(target, dest)
        assert result.exists()
        assert result.stat().st_size > 0

    def test_snapshot_jsonl_gz_creates_file(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path, fmt="jsonl.gz")
        dest = tmp_path / "backups" / "test-store" / "hourly" / "snap.jsonl.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        provider = FilesystemSnapshotProvider()
        result = provider.snapshot(target, dest)
        assert result.exists()
        assert result.stat().st_size > 0

    def test_snapshot_jsonl_gz_content_is_valid(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path, fmt="jsonl.gz")
        dest = tmp_path / "backups" / "test-store" / "hourly" / "snap.jsonl.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        provider = FilesystemSnapshotProvider()
        provider.snapshot(target, dest)
        with gzip.open(dest, "rt", encoding="utf-8") as fh:
            lines = fh.readlines()
        assert len(lines) > 0
        for line in lines:
            entry = json.loads(line)
            assert "path" in entry
            assert "is_dir" in entry
            assert "size" in entry

    def test_snapshot_missing_source_raises(self, tmp_path: Path) -> None:
        missing_source = tmp_path / "does-not-exist"
        target = BackupTarget(
            name="ghost",
            kind="snapshot",
            format="tar.gz",
            base_path=missing_source,
            rotation_policy=_make_policy(),
            encrypt_at_rest=False,
            checksum_required=False,
        )
        dest = tmp_path / "out.tar.gz"
        provider = FilesystemSnapshotProvider()
        with pytest.raises(FileNotFoundError):
            provider.snapshot(target, dest)

    def test_export_delegates_to_snapshot(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path, fmt="tar.gz")
        dest = tmp_path / "backups" / "test-store" / "hourly" / "export.tar.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        provider = FilesystemSnapshotProvider()
        result = provider.export(target, dest)
        assert result.exists()

    def test_unsupported_format_raises(self, tmp_path: Path) -> None:
        source = tmp_path / "source"
        source.mkdir()
        (source / "f.txt").write_text("x")
        target = BackupTarget(
            name="bad",
            kind="snapshot",
            format="tar.gz",  # type annotation is fine but we override at runtime
            base_path=source,
            rotation_policy=_make_policy(),
            encrypt_at_rest=False,
            checksum_required=False,
        )
        dest = tmp_path / "out.tar.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        provider = FilesystemSnapshotProvider()
        # Patch format after construction to simulate unsupported value
        object.__setattr__(target, "format", "unsupported")
        with pytest.raises(ValueError, match="unsupported backup format"):
            provider.snapshot(target, dest)


# ---------------------------------------------------------------------------
# BackupService.list_targets
# ---------------------------------------------------------------------------


class TestBackupServiceListTargets:
    def test_returns_all_registered_targets(self, tmp_path: Path) -> None:
        t1 = _make_target(tmp_path, name="alpha")
        t2 = _make_target(tmp_path, name="beta")
        svc = _make_service(tmp_path, [t1, t2])
        names = {t["name"] for t in svc.list_targets()}
        assert names == {"alpha", "beta"}

    def test_empty_targets(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, [])
        assert svc.list_targets() == []

    def test_target_dict_contains_base_path(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        svc = _make_service(tmp_path, [t])
        listing = svc.list_targets()
        assert len(listing) == 1
        assert "base_path" in listing[0]


# ---------------------------------------------------------------------------
# BackupService._get_target
# ---------------------------------------------------------------------------


class TestBackupServiceGetTarget:
    def test_unknown_target_raises_key_error(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, [])
        with pytest.raises(KeyError, match="unknown backup target"):
            svc._get_target("nonexistent")

    def test_empty_name_raises_value_error(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, [])
        with pytest.raises(ValueError, match="cannot be empty"):
            svc._get_target("   ")

    def test_known_target_returned(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, name="db")
        svc = _make_service(tmp_path, [t])
        result = svc._get_target("db")
        assert result.name == "db"


# ---------------------------------------------------------------------------
# BackupService._determine_rotation_tier
# ---------------------------------------------------------------------------


class TestDetermineRotationTier:
    def test_monthly_on_first_day(self) -> None:
        dt = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
        assert BackupService._determine_rotation_tier(dt) == "monthly"

    def test_weekly_on_sunday(self) -> None:
        # weekday() == 6 is Sunday
        dt = datetime(2026, 5, 3, 15, 0, 0, tzinfo=UTC)  # Sunday
        assert dt.weekday() == 6
        assert BackupService._determine_rotation_tier(dt) == "weekly"

    def test_daily_at_midnight(self) -> None:
        # Not first of month, not Sunday, hour == 0
        dt = datetime(2026, 5, 4, 0, 0, 0, tzinfo=UTC)  # Monday
        assert BackupService._determine_rotation_tier(dt) == "daily"

    def test_hourly_otherwise(self) -> None:
        dt = datetime(2026, 5, 18, 14, 30, 0, tzinfo=UTC)  # Monday, non-zero hour
        assert BackupService._determine_rotation_tier(dt) == "hourly"

    def test_monthly_takes_priority_over_sunday(self) -> None:
        # If day == 1 AND weekday == 6, monthly wins
        dt = datetime(2026, 3, 1, 0, 0, 0, tzinfo=UTC)
        assert BackupService._determine_rotation_tier(dt) == "monthly"


# ---------------------------------------------------------------------------
# BackupService.run_snapshot
# ---------------------------------------------------------------------------


class TestBackupServiceRunSnapshot:
    def test_run_snapshot_returns_manifest(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert isinstance(manifest, BackupManifest)

    def test_run_snapshot_artifact_exists(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert Path(manifest.backup_path).exists()

    def test_run_snapshot_sha256_populated(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz", checksum=True)
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert manifest.sha256 is not None
        assert len(manifest.sha256) == 64

    def test_run_snapshot_sha256_none_when_checksum_disabled(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz", checksum=False)
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert manifest.sha256 is None

    def test_run_snapshot_sidecar_written(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        artifact = Path(manifest.backup_path)
        sidecar = artifact.with_name(f"{artifact.name}.manifest.json")
        assert sidecar.exists()

    def test_run_snapshot_sidecar_is_valid_json(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        artifact = Path(manifest.backup_path)
        sidecar = artifact.with_name(f"{artifact.name}.manifest.json")
        data = json.loads(sidecar.read_text(encoding="utf-8"))
        assert data["target_name"] == t.name

    def test_run_snapshot_target_name_in_manifest(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, name="policy-store")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert manifest.target_name == "policy-store"

    def test_run_snapshot_unknown_target_raises(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, [])
        with pytest.raises(KeyError):
            svc.run_snapshot("nonexistent")

    def test_run_snapshot_jsonl_gz_format(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="jsonl.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert Path(manifest.backup_path).suffix == ".gz"
        assert manifest.backup_format == "jsonl.gz"

    def test_run_snapshot_encryption_flag_propagated(self, tmp_path: Path) -> None:
        t_enc = _make_target(tmp_path, name="enc", encrypt=True)
        t_plain = _make_target(tmp_path, name="plain", encrypt=False)
        svc = _make_service(tmp_path, [t_enc, t_plain])
        assert svc.run_snapshot("enc").encryption_applied is True
        assert svc.run_snapshot("plain").encryption_applied is False

    def test_run_snapshot_rotation_tier_assigned(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert manifest.rotation_tier in ("hourly", "daily", "weekly", "monthly")


# ---------------------------------------------------------------------------
# BackupService.run_export
# ---------------------------------------------------------------------------


class TestBackupServiceRunExport:
    def test_run_export_returns_manifest(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, kind="export", fmt="jsonl.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_export(t.name)
        assert isinstance(manifest, BackupManifest)

    def test_run_export_artifact_exists(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, kind="export", fmt="jsonl.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_export(t.name)
        assert Path(manifest.backup_path).exists()

    def test_run_export_unknown_target_raises(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, [])
        with pytest.raises(KeyError):
            svc.run_export("missing")

    def test_run_export_target_kind_preserved(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, kind="export", fmt="jsonl.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_export(t.name)
        assert manifest.target_kind == "export"


# ---------------------------------------------------------------------------
# BackupService.verify
# ---------------------------------------------------------------------------


class TestBackupServiceVerify:
    def test_verify_valid_manifest_passes(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path)
        svc = _make_service(tmp_path, [target])
        m = svc.run_snapshot(target.name)
        assert svc.verify(m) is True

    def test_verify_missing_file_fails(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path)
        svc = _make_service(tmp_path, [target])
        m = svc.run_snapshot(target.name)
        Path(m.backup_path).unlink()
        assert svc.verify(m) is False

    def test_verify_tampered_sha_fails(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path)
        svc = _make_service(tmp_path, [target])
        m = svc.run_snapshot(target.name)
        # Tamper: replace artifact content
        Path(m.backup_path).write_bytes(b"tampered")
        assert svc.verify(m) is False

    def test_verify_no_sha_passes_if_file_exists(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path, checksum=False)
        svc = _make_service(tmp_path, [target])
        m = svc.run_snapshot(target.name)
        # No sha256, file exists → passes
        assert svc.verify(m) is True

    def test_verify_nonexistent_path_returns_false(self, tmp_path: Path) -> None:
        target = _make_target(tmp_path)
        m = BackupManifest(
            target_name=target.name,
            target_kind=target.kind,
            backup_format=target.format,
            backup_path=str(tmp_path / "ghost.tar.gz"),
            created_at="2026-05-18T00:00:00Z",
            size_bytes=0,
            sha256="abc",
            rotation_tier="hourly",
            encryption_applied=False,
            meta={},
        )
        svc = _make_service(tmp_path, [target])
        assert svc.verify(m) is False


# ---------------------------------------------------------------------------
# BackupService.rotate
# ---------------------------------------------------------------------------


class TestBackupServiceRotate:
    def _seed_tier(
        self,
        root: Path,
        target_name: str,
        tier: str,
        count: int,
    ) -> list[Path]:
        tier_dir = root / target_name / tier
        tier_dir.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        for i in range(count):
            f = tier_dir / f"backup-{i:04d}.tar.gz"
            f.write_bytes(b"x" * (i + 1))
            files.append(f)
        return files

    def test_rotate_removes_excess_hourly(self, tmp_path: Path) -> None:
        policy = BackupRotationPolicy(max_hourly=3, max_daily=7, max_weekly=4, max_monthly=12)
        t = _make_target(tmp_path, policy=policy)
        root = tmp_path / "backups"
        root.mkdir(parents=True, exist_ok=True)
        self._seed_tier(root, t.name, "hourly", 6)
        svc = BackupService(root_backup_dir=root, targets=[t])
        removed = svc.rotate(t.name)
        assert len(removed) == 3

    def test_rotate_keeps_within_policy(self, tmp_path: Path) -> None:
        policy = BackupRotationPolicy(max_hourly=4, max_daily=7, max_weekly=4, max_monthly=12)
        t = _make_target(tmp_path, policy=policy)
        root = tmp_path / "backups"
        root.mkdir(parents=True, exist_ok=True)
        self._seed_tier(root, t.name, "hourly", 4)
        svc = BackupService(root_backup_dir=root, targets=[t])
        removed = svc.rotate(t.name)
        assert len(removed) == 0

    def test_rotate_removes_sidecar_with_artifact(self, tmp_path: Path) -> None:
        policy = BackupRotationPolicy(max_hourly=1, max_daily=7, max_weekly=4, max_monthly=12)
        t = _make_target(tmp_path, policy=policy)
        root = tmp_path / "backups"
        tier_dir = root / t.name / "hourly"
        tier_dir.mkdir(parents=True, exist_ok=True)
        # Create 2 artifacts + sidecars
        for i in range(2):
            artifact = tier_dir / f"backup-{i:04d}.tar.gz"
            artifact.write_bytes(b"x" * 10)
            sidecar = artifact.with_name(f"{artifact.name}.manifest.json")
            sidecar.write_text("{}", encoding="utf-8")
        svc = BackupService(root_backup_dir=root, targets=[t])
        svc.rotate(t.name)
        remaining = list(tier_dir.glob("*.tar.gz"))
        assert len(remaining) == 1
        # The removed artifact's sidecar should also be gone
        removed_artifact = tier_dir / "backup-0000.tar.gz"
        assert not removed_artifact.exists()
        assert not removed_artifact.with_name(f"{removed_artifact.name}.manifest.json").exists()

    def test_rotate_missing_tier_dir_is_noop(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        root = tmp_path / "backups"
        root.mkdir(parents=True, exist_ok=True)
        svc = BackupService(root_backup_dir=root, targets=[t])
        # No tier directories exist
        removed = svc.rotate(t.name)
        assert removed == []

    def test_rotate_unknown_target_raises(self, tmp_path: Path) -> None:
        svc = _make_service(tmp_path, [])
        with pytest.raises(KeyError):
            svc.rotate("ghost")


# ---------------------------------------------------------------------------
# BackupService: custom SnapshotProvider injection
# ---------------------------------------------------------------------------


class TestBackupServiceProviderInjection:
    def test_custom_provider_is_called_for_snapshot(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        artifact_path = tmp_path / "custom_artifact.tar.gz"
        artifact_path.write_bytes(b"custom")

        provider = MagicMock(spec=SnapshotProvider)
        provider.snapshot.return_value = artifact_path

        root = tmp_path / "backups"
        root.mkdir(parents=True, exist_ok=True)
        svc = BackupService(root_backup_dir=root, targets=[t], snapshot_provider=provider)
        svc.run_snapshot(t.name)
        provider.snapshot.assert_called_once()

    def test_custom_provider_is_called_for_export(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, kind="export", fmt="jsonl.gz")
        artifact_path = tmp_path / "custom_export.jsonl.gz"
        artifact_path.write_bytes(b"custom")

        provider = MagicMock(spec=SnapshotProvider)
        provider.export.return_value = artifact_path

        root = tmp_path / "backups"
        root.mkdir(parents=True, exist_ok=True)
        svc = BackupService(root_backup_dir=root, targets=[t], snapshot_provider=provider)
        svc.run_export(t.name)
        provider.export.assert_called_once()


# ---------------------------------------------------------------------------
# default_backup_targets_from_env
# ---------------------------------------------------------------------------


class TestDefaultBackupTargetsFromEnv:
    def test_always_includes_runtime_metadata(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        monkeypatch.setenv("IRONCLAW_RUNTIME_STATE_DIR", str(tmp_path / "output"))
        targets = default_backup_targets_from_env()
        names = {t.name for t in targets}
        assert "runtime-metadata" in names

    def test_database_target_included_when_db_url_set(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_DB_URL", "postgresql://localhost/ironclaw")
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        monkeypatch.setenv("IRONCLAW_RUNTIME_STATE_DIR", str(tmp_path / "output"))
        targets = default_backup_targets_from_env()
        names = {t.name for t in targets}
        assert "database" in names

    def test_database_target_absent_when_no_db_url(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        targets = default_backup_targets_from_env()
        names = {t.name for t in targets}
        assert "database" not in names

    def test_runtime_metadata_format_is_jsonl_gz(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        targets = default_backup_targets_from_env()
        rt = next(t for t in targets if t.name == "runtime-metadata")
        assert rt.format == "jsonl.gz"

    def test_database_target_format_is_tar_gz(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/ironclaw")
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        targets = default_backup_targets_from_env()
        db = next(t for t in targets if t.name == "database")
        assert db.format == "tar.gz"

    def test_custom_rotation_env_vars_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        monkeypatch.setenv("IRONCLAW_RUNTIME_BACKUP_MAX_HOURLY", "2")
        monkeypatch.setenv("IRONCLAW_RUNTIME_BACKUP_MAX_DAILY", "1")
        targets = default_backup_targets_from_env()
        rt = next(t for t in targets if t.name == "runtime-metadata")
        assert rt.rotation_policy.max_hourly == 2
        assert rt.rotation_policy.max_daily == 1

    def test_invalid_rotation_env_falls_back_to_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        monkeypatch.setenv("IRONCLAW_RUNTIME_BACKUP_MAX_HOURLY", "not-a-number")
        targets = default_backup_targets_from_env()
        rt = next(t for t in targets if t.name == "runtime-metadata")
        assert rt.rotation_policy.max_hourly == 6  # default


# ---------------------------------------------------------------------------
# build_default_backup_service
# ---------------------------------------------------------------------------


class TestBuildDefaultBackupService:
    def test_returns_backup_service_instance(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        monkeypatch.setenv("IRONCLAW_RUNTIME_STATE_DIR", str(tmp_path / "output"))
        svc = build_default_backup_service()
        assert isinstance(svc, BackupService)

    def test_service_has_runtime_metadata_target(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_DB_URL", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_BACKUP_ROOT", str(tmp_path / "backups"))
        monkeypatch.setenv("IRONCLAW_RUNTIME_STATE_DIR", str(tmp_path / "output"))
        svc = build_default_backup_service()
        names = {t["name"] for t in svc.list_targets()}
        assert "runtime-metadata" in names


# ---------------------------------------------------------------------------
# Restore round-trip (snapshot → verify → rotate)
# ---------------------------------------------------------------------------


class TestRestoreRoundTrip:
    def test_snapshot_verify_passes_immediately(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert svc.verify(manifest) is True

    def test_multiple_snapshots_accumulate(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, fmt="tar.gz")
        svc = _make_service(tmp_path, [t])
        m1 = svc.run_snapshot(t.name)
        m2 = svc.run_snapshot(t.name)
        assert Path(m1.backup_path).exists()
        assert Path(m2.backup_path).exists()

    def test_snapshot_then_rotate_removes_excess(self, tmp_path: Path) -> None:
        policy = BackupRotationPolicy(max_hourly=1, max_daily=7, max_weekly=4, max_monthly=12)
        t = _make_target(tmp_path, policy=policy)
        root = tmp_path / "backups"
        root.mkdir(parents=True, exist_ok=True)
        tier_dir = root / t.name / "hourly"
        tier_dir.mkdir(parents=True, exist_ok=True)
        # Pre-seed 3 old backups
        for i in range(3):
            f = tier_dir / f"old-{i:04d}.tar.gz"
            f.write_bytes(b"old")
        svc = BackupService(root_backup_dir=root, targets=[t])
        svc.rotate(t.name)
        remaining = [p for p in tier_dir.glob("*.tar.gz") if not p.name.endswith(".manifest.json")]
        assert len(remaining) <= policy.max_hourly

    def test_export_verify_passes(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path, kind="export", fmt="jsonl.gz")
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_export(t.name)
        assert svc.verify(manifest) is True

    def test_manifest_meta_contains_rotation_policy(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert "rotation_policy" in manifest.meta
        assert "max_hourly" in manifest.meta["rotation_policy"]

    def test_created_at_is_utc_iso_format(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert manifest.created_at.endswith("Z")

    def test_size_bytes_positive(self, tmp_path: Path) -> None:
        t = _make_target(tmp_path)
        svc = _make_service(tmp_path, [t])
        manifest = svc.run_snapshot(t.name)
        assert manifest.size_bytes > 0
