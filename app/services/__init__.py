from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .backupservice import (
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
    from .stix_adapter import (
        STIXAdapter,
        STIXParseResult,
        TAXIIConfig,
        get_stix_adapter,
        ingest_from_taxii,
        ingest_stix_bundle,
        ingest_stix_bundle_bytes,
        parse_stix_bundle,
    )
    from .telemetry_service import (
        TelemetryBatchResult,
        TelemetryEventInput,
        build_agent_event,
        build_event_key,
        post_telemetry_batch,
        post_telemetry_batch_async,
    )
    from .threat_alerts import emit_detection_alert, emit_hunt_alert, get_threat_alert_store
    from .threat_detection_engine import ThreatDetectionEngine, get_detection_engine
    from .threat_hunt_service import ThreatHuntService, get_threat_hunt_service
    from .threat_scoring import ScoreResult, ThreatScoringEngine, get_scoring_engine
    from .webhook_service import (
        WebhookDeliveryStatus,
        WebhookDispatchResult,
        deliver_webhook,
        dispatch_event,
        retry_failed_delivery,
    )

__all__ = [
    # Backup
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
    # Telemetry service
    "TelemetryBatchResult",
    "TelemetryEventInput",
    "build_agent_event",
    "build_event_key",
    "post_telemetry_batch",
    "post_telemetry_batch_async",
    # Threat scoring
    "ScoreResult",
    "ThreatScoringEngine",
    "get_scoring_engine",
    # Threat detection
    "ThreatDetectionEngine",
    "get_detection_engine",
    # Threat hunt
    "ThreatHuntService",
    "get_threat_hunt_service",
    # Threat alerts
    "emit_detection_alert",
    "emit_hunt_alert",
    "get_threat_alert_store",
    # STIX
    "STIXAdapter",
    "STIXParseResult",
    "TAXIIConfig",
    "get_stix_adapter",
    "ingest_from_taxii",
    "ingest_stix_bundle",
    "ingest_stix_bundle_bytes",
    "parse_stix_bundle",
    # Webhook
    "WebhookDeliveryStatus",
    "WebhookDispatchResult",
    "dispatch_event",
    "deliver_webhook",
    "retry_failed_delivery",
    "stripe_service",
]


def __getattr__(name: str) -> Any:
    if name in {
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
    }:
        from .backupservice import (
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

        return {
            "BackupFormat": BackupFormat,
            "BackupKind": BackupKind,
            "BackupManifest": BackupManifest,
            "BackupRotationPolicy": BackupRotationPolicy,
            "BackupService": BackupService,
            "BackupTarget": BackupTarget,
            "FilesystemSnapshotProvider": FilesystemSnapshotProvider,
            "RotationTier": RotationTier,
            "SnapshotProvider": SnapshotProvider,
            "build_default_backup_service": build_default_backup_service,
            "default_backup_targets_from_env": default_backup_targets_from_env,
        }[name]

    if name in {
        "STIXAdapter",
        "STIXParseResult",
        "TAXIIConfig",
        "get_stix_adapter",
        "ingest_from_taxii",
        "ingest_stix_bundle",
        "ingest_stix_bundle_bytes",
        "parse_stix_bundle",
    }:
        from .stix_adapter import (
            STIXAdapter,
            STIXParseResult,
            TAXIIConfig,
            get_stix_adapter,
            ingest_from_taxii,
            ingest_stix_bundle,
            ingest_stix_bundle_bytes,
            parse_stix_bundle,
        )

        return {
            "STIXAdapter": STIXAdapter,
            "STIXParseResult": STIXParseResult,
            "TAXIIConfig": TAXIIConfig,
            "get_stix_adapter": get_stix_adapter,
            "ingest_from_taxii": ingest_from_taxii,
            "ingest_stix_bundle": ingest_stix_bundle,
            "ingest_stix_bundle_bytes": ingest_stix_bundle_bytes,
            "parse_stix_bundle": parse_stix_bundle,
        }[name]

    if name in {
        "TelemetryBatchResult",
        "TelemetryEventInput",
        "build_agent_event",
        "build_event_key",
        "post_telemetry_batch",
        "post_telemetry_batch_async",
    }:
        from .telemetry_service import (
            TelemetryBatchResult,
            TelemetryEventInput,
            build_agent_event,
            build_event_key,
            post_telemetry_batch,
            post_telemetry_batch_async,
        )

        return {
            "TelemetryBatchResult": TelemetryBatchResult,
            "TelemetryEventInput": TelemetryEventInput,
            "build_agent_event": build_agent_event,
            "build_event_key": build_event_key,
            "post_telemetry_batch": post_telemetry_batch,
            "post_telemetry_batch_async": post_telemetry_batch_async,
        }[name]

    if name in {
        "emit_detection_alert",
        "emit_hunt_alert",
        "get_threat_alert_store",
    }:
        from .threat_alerts import (
            emit_detection_alert,
            emit_hunt_alert,
            get_threat_alert_store,
        )

        return {
            "emit_detection_alert": emit_detection_alert,
            "emit_hunt_alert": emit_hunt_alert,
            "get_threat_alert_store": get_threat_alert_store,
        }[name]

    if name in {
        "ThreatDetectionEngine",
        "get_detection_engine",
    }:
        from .threat_detection_engine import (
            ThreatDetectionEngine,
            get_detection_engine,
        )

        return {
            "ThreatDetectionEngine": ThreatDetectionEngine,
            "get_detection_engine": get_detection_engine,
        }[name]

    if name in {
        "ThreatHuntService",
        "get_threat_hunt_service",
    }:
        from .threat_hunt_service import (
            ThreatHuntService,
            get_threat_hunt_service,
        )

        return {
            "ThreatHuntService": ThreatHuntService,
            "get_threat_hunt_service": get_threat_hunt_service,
        }[name]

    if name in {
        "ScoreResult",
        "ThreatScoringEngine",
        "get_scoring_engine",
    }:
        from .threat_scoring import (
            ScoreResult,
            ThreatScoringEngine,
            get_scoring_engine,
        )

        return {
            "ScoreResult": ScoreResult,
            "ThreatScoringEngine": ThreatScoringEngine,
            "get_scoring_engine": get_scoring_engine,
        }[name]

    if name in {
        "WebhookDeliveryStatus",
        "WebhookDispatchResult",
        "deliver_webhook",
        "dispatch_event",
        "retry_failed_delivery",
    }:
        from .webhook_service import (
            WebhookDeliveryStatus,
            WebhookDispatchResult,
            deliver_webhook,
            dispatch_event,
            retry_failed_delivery,
        )

        return {
            "WebhookDeliveryStatus": WebhookDeliveryStatus,
            "WebhookDispatchResult": WebhookDispatchResult,
            "deliver_webhook": deliver_webhook,
            "dispatch_event": dispatch_event,
            "retry_failed_delivery": retry_failed_delivery,
        }[name]

    if name == "stripe_service":
        import importlib

        return importlib.import_module(f"{__name__}.stripe_service")

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
