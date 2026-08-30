"""Compatibility wrapper for legacy root-level API key imports.

This module intentionally re-exports the canonical implementation from
app.core.apikeys without duplicating the actual registry logic.
"""

from app.core.apikeys import (
    APIKeyRecord,
    APIKeyRegistry,
    authenticate_api_key,
    classify_api_key,
    constant_time_api_key_match,
    create_api_key,
    create_org_key,
    fingerprint_api_key,
    generate_api_key,
    generate_org_api_key,
    get_api_key_registry,
    mask_api_key,
    revoke_api_key,
    rotate_api_key,
    utc_now_iso,
)

ApiKeyRecord = APIKeyRecord
ApiKeyRegistry = APIKeyRegistry
registry = get_api_key_registry()

__all__ = [
    "APIKeyRecord",
    "APIKeyRegistry",
    "ApiKeyRecord",
    "ApiKeyRegistry",
    "authenticate_api_key",
    "classify_api_key",
    "constant_time_api_key_match",
    "create_api_key",
    "create_org_key",
    "fingerprint_api_key",
    "generate_api_key",
    "generate_org_api_key",
    "get_api_key_registry",
    "mask_api_key",
    "revoke_api_key",
    "rotate_api_key",
    "registry",
    "utc_now_iso",
]
