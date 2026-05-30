from __future__ import annotations

import importlib
import os
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest

# ---------------------------------------------------------------------------
# Helpers — always reload region module so lru_cache doesn't leak between tests
# ---------------------------------------------------------------------------


def _reload_region():
    import app.core.region as m

    importlib.reload(m)
    return m


# ---------------------------------------------------------------------------
# get_active_region()
# ---------------------------------------------------------------------------


def test_get_active_region_default_when_unset():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("IRONCLAW_REGION", None)
        m = _reload_region()
        result = m.get_active_region()
    assert result == m.RegionCode.US_EAST_1
    assert str(result) == "us-east-1"


def test_get_active_region_returns_correct_value_when_env_set():
    with patch.dict(os.environ, {"IRONCLAW_REGION": "eu-west-1"}, clear=False):
        m = _reload_region()
        result = m.get_active_region()
    assert result == m.RegionCode.EU_WEST_1
    assert str(result) == "eu-west-1"


def test_get_active_region_raises_on_unknown_region():
    with patch.dict(os.environ, {"IRONCLAW_REGION": "xx-invalid-9"}, clear=False):
        m = _reload_region()
        with pytest.raises(ValueError, match="Unknown region code"):
            m.get_active_region()


# ---------------------------------------------------------------------------
# get_region_configs()
# ---------------------------------------------------------------------------


def test_get_region_configs_returns_empty_when_no_regions_configured():
    env_overrides = {
        "PRIMARY_REGION": "us-east-1",
        "REPLICA_REGIONS": "",
        "HA_ENABLED": "false",
    }
    # Ensure none of the per-region URL vars are set
    clear_keys = [
        "REGION_US_EAST_1_SUPABASE_URL",
        "REGION_US_WEST_2_SUPABASE_URL",
        "REGION_EU_WEST_1_SUPABASE_URL",
        "REGION_AP_SOUTHEAST_1_SUPABASE_URL",
    ]
    with patch.dict(os.environ, env_overrides, clear=False):
        for k in clear_keys:
            os.environ.pop(k, None)
        m = _reload_region()
        m.get_multi_region_settings.cache_clear()
        configs = m.get_region_configs()
    assert configs == []


def test_get_region_configs_returns_primary_when_configured():
    env_overrides = {
        "PRIMARY_REGION": "us-east-1",
        "REPLICA_REGIONS": "",
        "HA_ENABLED": "false",
        "REGION_US_EAST_1_SUPABASE_URL": "https://primary.supabase.co",
        "REGION_US_EAST_1_SUPABASE_SERVICE_ROLE_KEY": "service-key-primary",
        "REGION_US_EAST_1_SUPABASE_ANON_KEY": "anon-key-primary",
    }
    with patch.dict(os.environ, env_overrides, clear=False):
        m = _reload_region()
        m.get_multi_region_settings.cache_clear()
        configs = m.get_region_configs()
    assert len(configs) == 1
    assert configs[0].is_primary is True
    assert str(configs[0].region_code) == "us-east-1"


# ---------------------------------------------------------------------------
# get_primary_region_config()
# ---------------------------------------------------------------------------


def test_get_primary_region_config_raises_when_none_configured():
    env_overrides = {
        "PRIMARY_REGION": "us-east-1",
        "REPLICA_REGIONS": "",
        "HA_ENABLED": "false",
    }
    clear_keys = [
        "REGION_US_EAST_1_SUPABASE_URL",
        "REGION_US_WEST_2_SUPABASE_URL",
        "REGION_EU_WEST_1_SUPABASE_URL",
        "REGION_AP_SOUTHEAST_1_SUPABASE_URL",
    ]
    with patch.dict(os.environ, env_overrides, clear=False):
        for k in clear_keys:
            os.environ.pop(k, None)
        m = _reload_region()
        m.get_multi_region_settings.cache_clear()
        with pytest.raises(RuntimeError, match="No primary region is configured"):
            m.get_primary_region_config()


# ---------------------------------------------------------------------------
# MultiRegionSettings.validate_ha_requires_replicas
# ---------------------------------------------------------------------------


def test_multi_region_settings_ha_enabled_with_empty_replicas_raises():
    env_overrides = {
        "HA_ENABLED": "true",
        "REPLICA_REGIONS": "",
        "PRIMARY_REGION": "us-east-1",
    }
    with patch.dict(os.environ, env_overrides, clear=False):
        m = _reload_region()
        with pytest.raises(Exception, match="HA_ENABLED=true requires at least one entry in REPLICA_REGIONS"):
            m.MultiRegionSettings()


def test_multi_region_settings_ha_enabled_with_replicas_is_valid():
    env_overrides = {
        "HA_ENABLED": "true",
        "REPLICA_REGIONS": "eu-west-1",
        "PRIMARY_REGION": "us-east-1",
    }
    with patch.dict(os.environ, env_overrides, clear=False):
        m = _reload_region()
        settings = m.MultiRegionSettings()
    assert settings.ha_enabled is True
    assert "eu-west-1" in settings.parsed_replica_codes()


# ---------------------------------------------------------------------------
# GET /region/status — 200 with expected response shape
# ---------------------------------------------------------------------------


def _make_test_app():
    from fastapi import FastAPI

    from app.api.region_status import router as region_router

    app = FastAPI()
    app.include_router(region_router)
    return app


def test_get_region_status_returns_200_with_expected_shape():
    env_overrides = {
        "PRIMARY_REGION": "us-east-1",
        "REPLICA_REGIONS": "",
        "HA_ENABLED": "false",
        "REGION_FAILOVER_ENABLED": "false",
        "REGION_HEALTH_CHECK_INTERVAL_SECONDS": "30",
        "IRONCLAW_REGION": "us-east-1",
    }
    clear_keys = [
        "REGION_US_EAST_1_SUPABASE_URL",
        "REGION_US_WEST_2_SUPABASE_URL",
        "REGION_EU_WEST_1_SUPABASE_URL",
        "REGION_AP_SOUTHEAST_1_SUPABASE_URL",
    ]
    with patch.dict(os.environ, env_overrides, clear=False):
        for k in clear_keys:
            os.environ.pop(k, None)
        m = _reload_region()
        m.get_multi_region_settings.cache_clear()

        app = _make_test_app()
        client = TestClient(app, raise_server_exceptions=True)
        response = client.get("/region/status")

    assert response.status_code == 200
    data = response.json()

    # Required top-level keys from RegionStatusResponse
    assert "active_region" in data
    assert "ha_enabled" in data
    assert "failover_enabled" in data
    assert "health_check_interval_seconds" in data
    assert "primary_region" in data
    assert "replica_regions" in data
    assert "regions" in data

    assert isinstance(data["ha_enabled"], bool)
    assert isinstance(data["failover_enabled"], bool)
    assert isinstance(data["health_check_interval_seconds"], int)
    assert isinstance(data["replica_regions"], list)
    assert isinstance(data["regions"], list)
    assert data["active_region"] == "us-east-1"
    assert data["ha_enabled"] is False
