from __future__ import annotations

from app.clients.release_policy_client import ReleasePolicyClient
from app.providers.service_registry import ServiceRegistry, build_service_registry

# Module-level singleton registry used across the app.
_service_registry: ServiceRegistry | None = None


def get_service_registry() -> ServiceRegistry:
    """Return the shared ServiceRegistry instance.

    The registry is created lazily on first access so that imports
    remain cheap and we avoid initialization ordering issues.
    """
    global _service_registry
    if _service_registry is None:
        _service_registry = build_service_registry()
    return _service_registry


def get_release_policy_client() -> ReleasePolicyClient:
    """Convenience accessor for the ReleasePolicyClient.

    This is the main entry point most callers will use when they need
    to evaluate release policy from routes, tasks, or scripts.
    """
    return get_service_registry().get_release_policy_client()


def _reset_dependencies_for_tests() -> None:
    """Test-only helper to reset the global registry.

    This should not be used in application code, but can be imported
    in test suites to ensure isolation between test cases.
    """
    global _service_registry
    _service_registry = None
