from __future__ import annotations

from app.clients.release_policy_client import ReleasePolicyClient
from app.persistencebootstrap import StoreType, get_persistence_store
from app.providers.service_registry import ServiceRegistry, build_service_registry
from app.services.authservice import AuthService

_service_registry: ServiceRegistry | None = None


def get_service_registry() -> ServiceRegistry:
    global _service_registry
    if _service_registry is None:
        _service_registry = build_service_registry()
    return _service_registry


def get_release_policy_client() -> ReleasePolicyClient:
    return get_service_registry().get_release_policy_client()


def get_auth_service() -> AuthService:
    return get_service_registry().get_auth_service()


def get_store() -> StoreType:
    return get_persistence_store()


def _reset_dependencies_for_tests() -> None:
    global _service_registry
    _service_registry = None


__all__ = [
    "ServiceRegistry",
    "_reset_dependencies_for_tests",
    "build_service_registry",
    "get_auth_service",
    "get_release_policy_client",
    "get_service_registry",
    "get_store",
]
