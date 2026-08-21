from __future__ import annotations

from app.clients.release_policy_client import ReleasePolicyClient
from app.core.billing import BillingRegistry, get_billing_registry
from app.core.install_keys import InstallKeyRegistry, get_install_key_registry
from app.core.unit_wallet import UnitWalletRegistry, get_unit_wallet_registry
from app.dependencies.hybrid_auth import (
    HybridAuthResult,
    get_hybrid_auth,
    get_org_id_from_hybrid,
    get_principal_from_hybrid,
    require_hybrid_auth,
    require_hybrid_auth_optional,
)
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
    "BillingRegistry",
    "HybridAuthResult",
    "InstallKeyRegistry",
    "ServiceRegistry",
    "UnitWalletRegistry",
    "_reset_dependencies_for_tests",
    "build_service_registry",
    "get_auth_service",
    "get_billing_registry",
    "get_hybrid_auth",
    "get_install_key_registry",
    "get_org_id_from_hybrid",
    "get_principal_from_hybrid",
    "get_release_policy_client",
    "get_service_registry",
    "get_store",
    "get_unit_wallet_registry",
    "require_hybrid_auth",
    "require_hybrid_auth_optional",
]
