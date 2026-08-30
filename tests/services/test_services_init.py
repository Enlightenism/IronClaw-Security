from __future__ import annotations

import importlib
import sys
import types

import pytest

MODULE_NAME = "app.services"


def _reload_services_module():
    sys.modules.pop(MODULE_NAME, None)
    return importlib.import_module(MODULE_NAME)


def _install_stub_module(
    module_name: str,
    attributes: dict[str, object],
) -> types.ModuleType:
    module = types.ModuleType(module_name)
    for key, value in attributes.items():
        setattr(module, key, value)
    sys.modules[module_name] = module
    return module


class TestServicesInitExports:
    def test_import_exposes_expected_all(self):
        services = _reload_services_module()

        assert isinstance(services.__all__, list)
        assert "BackupService" in services.__all__
        assert "STIXAdapter" in services.__all__
        assert "TelemetryBatchResult" in services.__all__
        assert "ThreatDetectionEngine" in services.__all__
        assert "ThreatHuntService" in services.__all__
        assert "ScoreResult" in services.__all__
        assert "WebhookDispatchResult" in services.__all__

    def test_dir_includes_all_exported_names(self):
        services = _reload_services_module()

        exported = set(services.__all__)
        listed = set(dir(services))

        assert exported.issubset(listed)

    def test_unknown_attribute_raises_attribute_error(self):
        services = _reload_services_module()

        with pytest.raises(AttributeError, match="has no attribute"):
            _ = services.DOES_NOT_EXIST

    def test_known_lazy_exports_resolve_without_eager_import(self):
        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()

        assert services.__getattr__("BackupService") is not None
        assert "app.services.backupservice" in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules


class TestServicesInitLazyLoading:
    def test_import_does_not_eagerly_import_service_submodules(self):
        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()

        assert services.__name__ == MODULE_NAME
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_backup_attribute_loads_only_backup_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.backupservice",
            {
                "BackupFormat": type("BackupFormat", (), {}),
                "BackupKind": type("BackupKind", (), {}),
                "BackupManifest": type("BackupManifest", (), {}),
                "BackupRotationPolicy": type("BackupRotationPolicy", (), {}),
                "BackupService": sentinel,
                "BackupTarget": type("BackupTarget", (), {}),
                "FilesystemSnapshotProvider": type(
                    "FilesystemSnapshotProvider",
                    (),
                    {},
                ),
                "RotationTier": type("RotationTier", (), {}),
                "SnapshotProvider": type("SnapshotProvider", (), {}),
                "build_default_backup_service": lambda: None,
                "default_backup_targets_from_env": lambda: [],
            },
        )

        for module_name in [
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.BackupService

        assert resolved is sentinel
        assert "app.services.backupservice" in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_stix_attribute_loads_only_stix_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.stix_adapter",
            {
                "STIXAdapter": sentinel,
                "STIXParseResult": type("STIXParseResult", (), {}),
                "TAXIIConfig": type("TAXIIConfig", (), {}),
                "get_stix_adapter": lambda: None,
                "ingest_from_taxii": lambda *args, **kwargs: None,
                "ingest_stix_bundle": lambda *args, **kwargs: None,
                "ingest_stix_bundle_bytes": lambda *args, **kwargs: None,
                "parse_stix_bundle": lambda *args, **kwargs: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.STIXAdapter

        assert resolved is sentinel
        assert "app.services.stix_adapter" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_telemetry_attribute_loads_only_telemetry_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.telemetry_service",
            {
                "TelemetryBatchResult": sentinel,
                "TelemetryEventInput": type("TelemetryEventInput", (), {}),
                "build_agent_event": lambda *args, **kwargs: None,
                "build_event_key": lambda *args, **kwargs: "key",
                "post_telemetry_batch": lambda *args, **kwargs: None,
                "post_telemetry_batch_async": lambda *args, **kwargs: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.TelemetryBatchResult

        assert resolved is sentinel
        assert "app.services.telemetry_service" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_threat_alert_attribute_loads_only_alerts_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.threat_alerts",
            {
                "emit_detection_alert": sentinel,
                "emit_hunt_alert": lambda *args, **kwargs: None,
                "get_threat_alert_store": lambda: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.emit_detection_alert

        assert resolved is sentinel
        assert "app.services.threat_alerts" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_threat_detection_attribute_loads_only_detection_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.threat_detection_engine",
            {
                "ThreatDetectionEngine": sentinel,
                "get_detection_engine": lambda: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.ThreatDetectionEngine

        assert resolved is sentinel
        assert "app.services.threat_detection_engine" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_threat_hunt_attribute_loads_only_hunt_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.threat_hunt_service",
            {
                "ThreatHuntService": sentinel,
                "get_threat_hunt_service": lambda: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_scoring",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.ThreatHuntService

        assert resolved is sentinel
        assert "app.services.threat_hunt_service" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_threat_scoring_attribute_loads_only_scoring_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.threat_scoring",
            {
                "ScoreResult": sentinel,
                "ThreatScoringEngine": type("ThreatScoringEngine", (), {}),
                "get_scoring_engine": lambda: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.webhook_service",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.ScoreResult

        assert resolved is sentinel
        assert "app.services.threat_scoring" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.webhook_service" not in sys.modules

    def test_webhook_attribute_loads_only_webhook_module(self):
        sentinel = object()
        _install_stub_module(
            "app.services.webhook_service",
            {
                "WebhookDeliveryStatus": sentinel,
                "WebhookDispatchResult": type("WebhookDispatchResult", (), {}),
                "deliver_webhook": lambda *args, **kwargs: None,
                "dispatch_event": lambda *args, **kwargs: None,
                "retry_failed_delivery": lambda *args, **kwargs: None,
            },
        )

        for module_name in [
            "app.services.backupservice",
            "app.services.stix_adapter",
            "app.services.telemetry_service",
            "app.services.threat_alerts",
            "app.services.threat_detection_engine",
            "app.services.threat_hunt_service",
            "app.services.threat_scoring",
        ]:
            sys.modules.pop(module_name, None)

        services = _reload_services_module()
        resolved = services.WebhookDeliveryStatus

        assert resolved is sentinel
        assert "app.services.webhook_service" in sys.modules
        assert "app.services.backupservice" not in sys.modules
        assert "app.services.stix_adapter" not in sys.modules
        assert "app.services.telemetry_service" not in sys.modules
        assert "app.services.threat_alerts" not in sys.modules
        assert "app.services.threat_detection_engine" not in sys.modules
        assert "app.services.threat_hunt_service" not in sys.modules
        assert "app.services.threat_scoring" not in sys.modules
