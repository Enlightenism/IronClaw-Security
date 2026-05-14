from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

BackupKind = Literal["snapshot", "export"]
BackupFormat = Literal["tar.gz", "jsonl.gz"]
RotationTier = Literal["hourly", "daily", "weekly", "monthly"]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _timestamp_slug(dt: datetime | None = None) -> str:
    value = dt or _utc_now()
    return value.strftime("%Y%m%dT%H%M%SZ")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True, slots=True)
class BackupRotationPolicy:
    """Simple rotation policy expressed as max counts per tier."""

    max_hourly: int = 24
    max_daily: int = 7
    max_weekly: int = 4
    max_monthly: int = 12

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BackupTarget:
    """Logical store that can be snapshotted or exported."""

    name: str
    kind: BackupKind
    format: BackupFormat
    base_path: Path
    rotation_policy: BackupRotationPolicy
    encrypt_at_rest: bool = True
    checksum_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["base_path"] = str(self.base_path)
        return data


@dataclass(frozen=True, slots=True)
class BackupManifest:
    target_name: str
    target_kind: BackupKind
    backup_format: BackupFormat
    backup_path: str
    created_at: str
    size_bytes: int
    sha256: str | None
    rotation_tier: RotationTier
    encryption_applied: bool
    meta: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class SnapshotProvider(Protocol):
    """Abstraction for persistence stores to produce snapshot/export artifacts."""

    def snapshot(self, target: BackupTarget, destination: Path) -> Path: ...
    def export(self, target: BackupTarget, destination: Path) -> Path: ...


class FilesystemSnapshotProvider:
    """Default provider that copies or compresses directories/files.

    This is primarily for local development and CI artifacts; production
    integrations should provide a more robust implementation.
    """

    def snapshot(self, target: BackupTarget, destination: Path) -> Path:
        _ensure_dir(destination.parent)
        source = target.base_path
        if not source.exists():
            raise FileNotFoundError(f"snapshot source does not exist: {source}")

        if target.format == "tar.gz":
            archive_prefix = destination.parent / destination.name.removesuffix(".tar.gz")
            root_dir = source.parent
            base_name = source.name
            produced = Path(
                shutil.make_archive(
                    str(archive_prefix),
                    "gztar",
                    root_dir=str(root_dir),
                    base_dir=base_name,
                ),
            )
            if produced != destination:
                destination.unlink(missing_ok=True)
                produced.replace(destination)
            return destination

        if target.format == "jsonl.gz":
            entries: list[dict[str, Any]] = []
            for path in sorted(source.rglob("*")):
                entries.append(
                    {
                        "path": str(path.relative_to(source)),
                        "is_dir": path.is_dir(),
                        "size": path.stat().st_size if path.is_file() else 0,
                    },
                )
            with gzip.open(destination, "wt", encoding="utf-8") as fh:
                for entry in entries:
                    fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            return destination

        raise ValueError(f"unsupported backup format for snapshot: {target.format}")

    def export(self, target: BackupTarget, destination: Path) -> Path:
        return self.snapshot(target, destination)


class BackupService:
    """Orchestrates IronClaw backup creation, rotation, and verification.

    This service is intentionally filesystem-focused; callers are expected
    to provide the concrete SnapshotProvider that knows how to talk to
    databases, object stores, or other persistence layers.
    """

    def __init__(
        self,
        root_backup_dir: Path,
        targets: list[BackupTarget],
        snapshot_provider: SnapshotProvider | None = None,
    ) -> None:
        self._root = root_backup_dir
        self._targets: dict[str, BackupTarget] = {t.name: t for t in targets}
        self._provider: SnapshotProvider = snapshot_provider or FilesystemSnapshotProvider()

    def list_targets(self) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self._targets.values()]

    def run_snapshot(self, target_name: str) -> BackupManifest:
        target = self._get_target(target_name)
        current_time = _utc_now()
        tier = self._determine_rotation_tier(current_time)
        path = self._build_backup_path(target, tier, current_time)
        artifact = self._provider.snapshot(target, path)
        return self._finalize_manifest(target, artifact, tier, current_time)

    def run_export(self, target_name: str) -> BackupManifest:
        target = self._get_target(target_name)
        current_time = _utc_now()
        tier = self._determine_rotation_tier(current_time)
        path = self._build_backup_path(target, tier, current_time)
        artifact = self._provider.export(target, path)
        return self._finalize_manifest(target, artifact, tier, current_time)

    def rotate(self, target_name: str) -> list[Path]:
        target = self._get_target(target_name)
        removed: list[Path] = []
        policy = target.rotation_policy

        for tier, max_count in (
            ("hourly", policy.max_hourly),
            ("daily", policy.max_daily),
            ("weekly", policy.max_weekly),
            ("monthly", policy.max_monthly),
        ):
            tier_dir = self._tier_dir(target, tier)
            if not tier_dir.exists():
                continue
            backups = sorted(
                (p for p in tier_dir.glob("*") if p.is_file() and not p.name.endswith(".manifest.json")),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in backups[max_count:]:
                old.unlink(missing_ok=True)
                sidecar = self._manifest_sidecar_path(old)
                sidecar.unlink(missing_ok=True)
                removed.append(old)

        return removed

    def verify(self, manifest: BackupManifest) -> bool:
        path = Path(manifest.backup_path)
        if not path.exists() or not path.is_file():
            return False
        if manifest.sha256:
            current = _sha256_file(path)
            return current == manifest.sha256
        return True

    def _get_target(self, target_name: str) -> BackupTarget:
        normalized = target_name.strip()
        if not normalized:
            raise ValueError("target_name cannot be empty")
        try:
            return self._targets[normalized]
        except KeyError:
            raise KeyError(f"unknown backup target: {normalized}") from None

    @staticmethod
    def _determine_rotation_tier(dt: datetime) -> RotationTier:
        if dt.day == 1:
            return "monthly"
        if dt.weekday() == 6:
            return "weekly"
        if dt.hour == 0:
            return "daily"
        return "hourly"

    def _build_backup_path(self, target: BackupTarget, tier: RotationTier, dt: datetime) -> Path:
        slug = _timestamp_slug(dt)
        tier_dir = self._tier_dir(target, tier)
        _ensure_dir(tier_dir)
        suffix = ".tar.gz" if target.format == "tar.gz" else ".jsonl.gz"
        filename = f"{target.name}-{tier}-{slug}{suffix}"
        return tier_dir / filename

    def _tier_dir(self, target: BackupTarget, tier: RotationTier) -> Path:
        return self._root / target.name / tier

    @staticmethod
    def _manifest_sidecar_path(artifact: Path) -> Path:
        return artifact.with_name(f"{artifact.name}.manifest.json")

    def _finalize_manifest(
        self,
        target: BackupTarget,
        artifact: Path,
        tier: RotationTier,
        created_at: datetime,
    ) -> BackupManifest:
        size = artifact.stat().st_size if artifact.exists() else 0
        sha = _sha256_file(artifact) if target.checksum_required and artifact.exists() else None

        manifest = BackupManifest(
            target_name=target.name,
            target_kind=target.kind,
            backup_format=target.format,
            backup_path=str(artifact),
            created_at=_iso(created_at) or "",
            size_bytes=size,
            sha256=sha,
            rotation_tier=tier,
            encryption_applied=target.encrypt_at_rest,
            meta={"rotation_policy": target.rotation_policy.to_dict()},
        )
        self._write_manifest_sidecar(artifact, manifest)
        return manifest

    def _write_manifest_sidecar(self, artifact: Path, manifest: BackupManifest) -> None:
        sidecar = self._manifest_sidecar_path(artifact)
        _ensure_dir(sidecar.parent)
        sidecar.write_text(
            json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def default_backup_targets_from_env() -> list[BackupTarget]:
    """Construct a default set of backup targets from environment variables.

    This keeps orchestration logic centralized while allowing deployment
    configuration to drive which stores are actually backed up.
    """
    root = Path(os.getenv("IRONCLAW_BACKUP_ROOT", "backups")).resolve()

    db_url = os.getenv("SUPABASE_DB_URL") or os.getenv("DATABASE_URL") or ""
    db_enabled = bool(db_url)

    targets: list[BackupTarget] = []

    if db_enabled:
        db_policy = BackupRotationPolicy(
            max_hourly=_env_int("IRONCLAW_DB_BACKUP_MAX_HOURLY", 24),
            max_daily=_env_int("IRONCLAW_DB_BACKUP_MAX_DAILY", 7),
            max_weekly=_env_int("IRONCLAW_DB_BACKUP_MAX_WEEKLY", 4),
            max_monthly=_env_int("IRONCLAW_DB_BACKUP_MAX_MONTHLY", 12),
        )
        targets.append(
            BackupTarget(
                name="database",
                kind="snapshot",
                format="tar.gz",
                base_path=root / "database-source",
                rotation_policy=db_policy,
                encrypt_at_rest=True,
                checksum_required=True,
            ),
        )

    runtime_policy = BackupRotationPolicy(
        max_hourly=_env_int("IRONCLAW_RUNTIME_BACKUP_MAX_HOURLY", 6),
        max_daily=_env_int("IRONCLAW_RUNTIME_BACKUP_MAX_DAILY", 3),
        max_weekly=_env_int("IRONCLAW_RUNTIME_BACKUP_MAX_WEEKLY", 2),
        max_monthly=_env_int("IRONCLAW_RUNTIME_BACKUP_MAX_MONTHLY", 1),
    )
    targets.append(
        BackupTarget(
            name="runtime-metadata",
            kind="export",
            format="jsonl.gz",
            base_path=Path(os.getenv("IRONCLAW_RUNTIME_STATE_DIR", "output")).resolve(),
            rotation_policy=runtime_policy,
            encrypt_at_rest=False,
            checksum_required=True,
        ),
    )

    return targets


def build_default_backup_service() -> BackupService:
    root = Path(os.getenv("IRONCLAW_BACKUP_ROOT", "backups")).resolve()
    targets = default_backup_targets_from_env()
    return BackupService(root_backup_dir=root, targets=targets)


__all__ = [
    "BackupFormat",
    "BackupKind",
    "BackupManifest",
    "BackupRotationPolicy",
    "BackupService",
    "BackupTarget",
    "FilesystemSnapshotProvider",
    "RotationTier",
    "SnapshotProvider",
    "build_default_backup_service",
    "default_backup_targets_from_env",
]
