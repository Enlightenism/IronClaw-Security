from __future__ import annotations

from dataclasses import dataclass, field

from app.clients.release_policy_client import ReleasePolicyClient
from app.services.authservice import AuthService


@dataclass
class ServiceRegistry:
    """Lightweight registry/factory for shared service clients.

    This keeps construction in one place so the rest of the app can
    depend on stable, lazily‑created instances.
    """

    _release_policy_client: ReleasePolicyClient | None = field(
        default=None,
        init=False,
        repr=False,
    )

    _auth_service: AuthService | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def get_release_policy_client(self) -> ReleasePolicyClient:
        """Return a singleton ReleasePolicyClient instance.

        The client is created lazily on first access to avoid import
        cycles during application startup.
        """
        if self._release_policy_client is None:
            self._release_policy_client = ReleasePolicyClient()
        return self._release_policy_client

    def get_auth_service(self) -> AuthService:
        """Return a singleton AuthService instance.

        Created lazily on first access with default SessionPolicy so
        callers in routes and tasks receive the same stateless instance.
        """
        if self._auth_service is None:
            self._auth_service = AuthService()
        return self._auth_service


def build_service_registry() -> ServiceRegistry:
    """Factory for a ServiceRegistry instance.

    Hook this into your app startup so other modules can import a
    single registry and retrieve shared services as needed.
    """
    return ServiceRegistry()
