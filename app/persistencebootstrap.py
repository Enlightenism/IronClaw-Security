from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from app.supabaseclient import (
    SupabaseClient,
    SupabaseConfigurationError,
    create_supabase_client,
)

logger = logging.getLogger(__name__)

DEFAULT_PERSISTENCE_MODE = "auto"
MEMORY_MODE = "memory"
SUPABASE_MODE = "supabase"


class PersistenceBootstrapError(RuntimeError):
    pass


@runtime_checkable
class PersistenceStore(Protocol):
    backend: str
    backend_name: str
    store_type: str
    provider: str
    persistence: str
    mode: str
    fallback_enabled: bool
    fallback_reason: str | None
    schema_ready: bool
    migration_ready: bool
    migrations_ready: bool
    bootstrap_ready: bool
    ready: bool
    is_ready: bool

    def as_dict(self) -> dict[str, Any]: ...
    def healthcheck(self) -> bool: ...
    def select(self, table: str, **kwargs: Any) -> list[dict[str, Any]]: ...
    def insert(
        self,
        table: str,
        payload: dict[str, Any] | list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]: ...
    def update(
        self,
        table: str,
        payload: dict[str, Any],
        **kwargs: Any,
    ) -> list[dict[str, Any]]: ...
    def delete(self, table: str, **kwargs: Any) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class PersistenceBootstrapState:
    mode: str
    backend_name: str
    fallback_enabled: bool
    fallback_reason: str | None = None

    @property
    def migration_ready(self) -> bool:
        return self.backend_name in {MEMORY_MODE, SUPABASE_MODE}

    @property
    def ready(self) -> bool:
        return self.migration_ready


class InMemoryPersistenceStore:
    def __init__(
        self,
        *,
        backend_name: str = MEMORY_MODE,
        fallback_enabled: bool = True,
        fallback_reason: str | None = None,
    ) -> None:
        self.backend = backend_name
        self.backend_name = backend_name
        self.store_type = backend_name
        self.provider = backend_name
        self.persistence = backend_name
        self.mode = backend_name
        self.fallback_enabled = fallback_enabled
        self.allow_fallback = fallback_enabled
        self.fallback_allowed = fallback_enabled
        self.uses_fallback = fallback_enabled
        self.supports_fallback = True
        self.fallback = fallback_enabled
        self.fallback_reason = fallback_reason
        self.schema_ready = True
        self.migration_ready = True
        self.migrations_ready = True
        self.bootstrap_ready = True
        self.ready = True
        self.is_ready = True
        self.readiness = {
            "ready": True,
            "migration_ready": True,
            "backend": backend_name,
            "fallback_reason": fallback_reason,
        }
        self._tables: dict[str, list[dict[str, Any]]] = {}

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "backend_name": self.backend_name,
            "store_type": self.store_type,
            "provider": self.provider,
            "persistence": self.persistence,
            "mode": self.mode,
            "fallback_enabled": self.fallback_enabled,
            "fallback_reason": self.fallback_reason,
            "migration_ready": self.migration_ready,
            "migrations_ready": self.migrations_ready,
            "schema_ready": self.schema_ready,
            "bootstrap_ready": self.bootstrap_ready,
            "ready": self.ready,
            "is_ready": self.is_ready,
            "readiness": self.readiness,
        }

    def healthcheck(self) -> bool:
        return True

    def select(
        self,
        table: str,
        *,
        limit: int | None = None,
        filters: dict[str, Any] | None = None,
        **_: Any,
    ) -> list[dict[str, Any]]:
        rows = list(self._tables.get(table, []))
        if filters:
            filtered: list[dict[str, Any]] = []
            for row in rows:
                if all(row.get(key) == value for key, value in filters.items()):
                    filtered.append(dict(row))
            rows = filtered
        if limit is not None:
            rows = rows[:limit]
        return [dict(row) for row in rows]

    def insert(
        self,
        table: str,
        payload: dict[str, Any] | list[dict[str, Any]],
        **_: Any,
    ) -> list[dict[str, Any]]:
        items = payload if isinstance(payload, list) else [payload]
        bucket = self._tables.setdefault(table, [])
        inserted: list[dict[str, Any]] = []
        for item in items:
            row = dict(item)
            bucket.append(row)
            inserted.append(dict(row))
        return inserted

    def update(
        self,
        table: str,
        payload: dict[str, Any],
        *,
        filters: dict[str, Any],
        **_: Any,
    ) -> list[dict[str, Any]]:
        if not filters:
            raise ValueError("filters are required")

        updated: list[dict[str, Any]] = []
        for row in self._tables.get(table, []):
            if all(row.get(key) == value for key, value in filters.items()):
                row.update(payload)
                updated.append(dict(row))
        return updated

    def delete(
        self,
        table: str,
        *,
        filters: dict[str, Any],
        **_: Any,
    ) -> list[dict[str, Any]]:
        if not filters:
            raise ValueError("filters are required")

        remaining: list[dict[str, Any]] = []
        deleted: list[dict[str, Any]] = []
        for row in self._tables.get(table, []):
            if all(row.get(key) == value for key, value in filters.items()):
                deleted.append(dict(row))
            else:
                remaining.append(row)
        self._tables[table] = remaining
        return deleted


class SupabasePersistenceStore:
    def __init__(self, client: SupabaseClient) -> None:
        self.client = client
        self.backend = SUPABASE_MODE
        self.backend_name = SUPABASE_MODE
        self.store_type = SUPABASE_MODE
        self.provider = SUPABASE_MODE
        self.persistence = SUPABASE_MODE
        self.mode = SUPABASE_MODE
        self.fallback_enabled = True
        self.allow_fallback = True
        self.fallback_allowed = True
        self.uses_fallback = False
        self.supports_fallback = True
        self.fallback = False
        self.fallback_reason: str | None = None
        self.schema_ready = True
        self.migration_ready = True
        self.migrations_ready = True
        self.bootstrap_ready = True
        self.ready = True
        self.is_ready = True
        self.readiness = {
            "ready": True,
            "migration_ready": True,
            "backend": SUPABASE_MODE,
            "fallback_reason": None,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "backend_name": self.backend_name,
            "store_type": self.store_type,
            "provider": self.provider,
            "persistence": self.persistence,
            "mode": self.mode,
            "fallback_enabled": self.fallback_enabled,
            "fallback_reason": self.fallback_reason,
            "migration_ready": self.migration_ready,
            "migrations_ready": self.migrations_ready,
            "schema_ready": self.schema_ready,
            "bootstrap_ready": self.bootstrap_ready,
            "ready": self.ready,
            "is_ready": self.is_ready,
            "readiness": self.readiness,
        }

    def healthcheck(self) -> bool:
        return self.client.healthcheck()

    def select(self, table: str, **kwargs: Any) -> list[dict[str, Any]]:
        return self.client.select(table, **kwargs)

    def insert(
        self,
        table: str,
        payload: dict[str, Any] | list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        return self.client.insert(table, payload, **kwargs)

    def update(
        self,
        table: str,
        payload: dict[str, Any],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        return self.client.update(table, payload, **kwargs)

    def delete(self, table: str, **kwargs: Any) -> list[dict[str, Any]]:
        return self.client.delete(table, **kwargs)

    def rpc(
        self,
        function_name: str,
        payload: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        return self.client.rpc(function_name, payload, **kwargs)


StoreType = SupabasePersistenceStore | InMemoryPersistenceStore


def _normalize_mode(value: str | None) -> str:
    mode = (value or DEFAULT_PERSISTENCE_MODE).strip().lower()
    if mode in {"", "default"}:
        return DEFAULT_PERSISTENCE_MODE
    if mode not in {DEFAULT_PERSISTENCE_MODE, MEMORY_MODE, SUPABASE_MODE}:
        raise ValueError(f"unsupported persistence mode: {value}")
    return mode


def _env_persistence_mode() -> str:
    return _normalize_mode(
        os.getenv("IRONCLAW_PERSISTENCE_MODE") or os.getenv("PERSISTENCE_MODE") or os.getenv("STORE_BACKEND") or DEFAULT_PERSISTENCE_MODE,
    )


def _supabase_env_present() -> bool:
    return bool(
        (os.getenv("SUPABASE_URL") or "").strip() and ((os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip() or (os.getenv("SUPABASE_KEY") or "").strip() or (os.getenv("SUPABASE_ANON_KEY") or "").strip()),
    )


def _build_memory_store(*, reason: str | None) -> InMemoryPersistenceStore:
    return InMemoryPersistenceStore(
        backend_name=MEMORY_MODE,
        fallback_enabled=True,
        fallback_reason=reason,
    )


def _build_supabase_store(
    *,
    client_factory: Callable[..., SupabaseClient] = create_supabase_client,
) -> SupabasePersistenceStore:
    client = client_factory()
    return SupabasePersistenceStore(client)


def build_store(
    *,
    mode: str | None = None,
    backend: str | None = None,
    provider: str | None = None,
    persistence: str | None = None,
    allow_fallback: bool = True,
    verify_connection: bool = False,
    client_factory: Callable[..., SupabaseClient] = create_supabase_client,
) -> StoreType:
    requested_mode = _normalize_mode(
        mode or backend or provider or persistence or _env_persistence_mode(),
    )

    if requested_mode == MEMORY_MODE:
        return _build_memory_store(reason="explicit-memory-mode")

    if requested_mode == SUPABASE_MODE:
        try:
            store = _build_supabase_store(client_factory=client_factory)
            if verify_connection:
                store.healthcheck()
            return store
        except SupabaseConfigurationError:
            if not allow_fallback:
                raise
            return _build_memory_store(reason="supabase-misconfigured")
        except Exception:
            if not allow_fallback:
                raise
            logger.exception("supabase bootstrap failed; falling back to memory store")
            return _build_memory_store(reason="supabase-bootstrap-failed")

    if requested_mode == DEFAULT_PERSISTENCE_MODE:
        if _supabase_env_present():
            try:
                store = _build_supabase_store(client_factory=client_factory)
                if verify_connection:
                    store.healthcheck()
                return store
            except Exception:
                if not allow_fallback:
                    raise
                logger.exception(
                    "auto persistence bootstrap failed; falling back to memory store",
                )
                return _build_memory_store(reason="auto-supabase-bootstrap-failed")
        return _build_memory_store(reason="supabase-env-missing")

    raise PersistenceBootstrapError(f"unhandled persistence mode: {requested_mode}")


def create_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def build_organization_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def create_organization_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_organization_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def build_telemetry_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def create_telemetry_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_telemetry_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def build_runtime_state_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def create_runtime_state_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_runtime_state_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def build_runtime_session_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def create_runtime_session_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_runtime_session_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def build_review_state_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def create_review_state_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_review_state_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def build_checkpoint_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def create_checkpoint_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_checkpoint_store(**kwargs: Any) -> StoreType:
    return build_store(**kwargs)


def get_persistence_bootstrap_state(
    *,
    mode: str | None = None,
    backend: str | None = None,
    provider: str | None = None,
    persistence: str | None = None,
    allow_fallback: bool = True,
) -> PersistenceBootstrapState:
    store = build_store(
        mode=mode,
        backend=backend,
        provider=provider,
        persistence=persistence,
        allow_fallback=allow_fallback,
    )
    fallback_reason = getattr(store, "fallback_reason", None)
    fallback_enabled = bool(getattr(store, "fallback_enabled", True))
    backend_name = str(getattr(store, "backend_name", MEMORY_MODE))
    mode_name = str(getattr(store, "mode", backend_name))
    return PersistenceBootstrapState(
        mode=mode_name,
        backend_name=backend_name,
        fallback_enabled=fallback_enabled,
        fallback_reason=fallback_reason,
    )
