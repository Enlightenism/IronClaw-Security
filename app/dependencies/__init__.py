from __future__ import annotations

from app.clients.release_policy_client import ReleasePolicyClient
from app.providers.service_registry import ServiceRegistry, build_service_registry

_service_registry: ServiceRegistry | None = None


def get_service_registry() -> ServiceRegistry:
    global _service_registry
    if _service_registry is None:
        _service_registry = build_service_registry()
    return _service_registry


def get_release_policy_client() -> ReleasePolicyClient:
    return get_service_registry().get_release_policy_client()


def _reset_dependencies_for_tests() -> None:
    global _service_registry
    _service_registry = None


__all__ = [
    "ServiceRegistry",
    "build_service_registry",
    "get_service_registry",
    "get_release_policy_client",
    "_reset_dependencies_for_tests",
]