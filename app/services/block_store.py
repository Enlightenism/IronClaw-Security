"""Block record store: one append-only record per return-gate or install-gate block, scoped by owner key. Holds no raw agent content."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
import os
import re
import threading
from typing import Any, Final
import uuid

from app.supabaseclient import get_supabase_client, is_supabase_configured

logger = logging.getLogger(__name__)

TABLE_NAME: Final[str] = "runtime_blocks"
GATE_RETURN: Final[str] = "return"
GATE_INSTALL: Final[str] = "install"
VERDICT_BLOCK: Final[str] = "block"
UNKNOWN_PLATFORM: Final[str] = "unknown"
UNSPECIFIED_REASON: Final[str] = "unspecified"
MAX_OWNER_KEY_CHARS: Final[int] = 256
MAX_REASON_CODES: Final[int] = 16
MAX_REASON_CHARS: Final[int] = 512
MAX_MEMORY_RECORDS: Final[int] = 10_000
DEFAULT_LIST_LIMIT: Final[int] = 50
MAX_LIST_LIMIT: Final[int] = 500

_GATES: Final[frozenset[str]] = frozenset({GATE_RETURN, GATE_INSTALL})
_PLATFORM_PATTERN: Final[re.Pattern[str]] = re.compile(r"[a-z0-9_.-]{1,64}")
_REASON_CODE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def normalize_owner_key(owner_key: str | None) -> str | None:
    if owner_key is None:
        return None
    normalized = owner_key.strip().lower()[:MAX_OWNER_KEY_CHARS]
    return normalized or None


def _normalize_platform(platform: str) -> str:
    candidate = platform.strip().lower()
    return candidate if _PLATFORM_PATTERN.fullmatch(candidate) else UNKNOWN_PLATFORM


def _reason_text(reason_codes: Iterable[object]) -> str:
    # Only bounded reason codes are kept; free-form text (which may carry agent content) is dropped.
    codes = [str(code) for code in reason_codes]
    accepted = [code for code in dict.fromkeys(codes) if _REASON_CODE_PATTERN.fullmatch(code)][:MAX_REASON_CODES]
    if not accepted:
        return UNSPECIFIED_REASON
    return ",".join(accepted)[:MAX_REASON_CHARS]


@dataclass(frozen=True)
class BlockRecord:
    gate: str
    platform: str
    reason: str
    owner_key: str | None
    block_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    verdict: str = VERDICT_BLOCK
    created_at: str = field(default_factory=_now_iso)

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.block_id,
            "owner_key": self.owner_key,
            "platform": self.platform,
            "gate": self.gate,
            "reason": self.reason,
            "verdict": self.verdict,
            "created_at": self.created_at,
        }


class _MemoryBlockStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: deque[BlockRecord] = deque(maxlen=MAX_MEMORY_RECORDS)

    def insert(self, record: BlockRecord) -> None:
        with self._lock:
            self._records.append(record)

    def list_for_owner(self, owner_key: str, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            matches = [record.to_row() for record in reversed(self._records) if record.owner_key == owner_key]
        return matches[:limit]

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


_MEMORY_STORE: Final[_MemoryBlockStore] = _MemoryBlockStore()


def _use_supabase() -> bool:
    if os.environ.get("IRONCLAW_PERSISTENCE_MODE", "").strip().lower() == "memory":
        return False
    return is_supabase_configured()


def _insert_supabase(record: BlockRecord) -> None:
    client = get_supabase_client()
    client.table(TABLE_NAME).insert(record.to_row()).execute()


def _list_supabase(owner_key: str, limit: int) -> list[dict[str, Any]]:
    client = get_supabase_client()
    rows = client.table(TABLE_NAME).select("*").eq("owner_key", owner_key).order("created_at", desc=True).limit(limit).execute().data
    return list(rows or [])


def record_block(*, gate: str, platform: str, reason_codes: Iterable[object], owner_key: str | None) -> bool:
    if gate not in _GATES:
        logger.error("runtime block rejected: unknown gate", extra={"gate": gate})
        return False

    record = BlockRecord(
        gate=gate,
        platform=_normalize_platform(platform),
        reason=_reason_text(reason_codes),
        owner_key=normalize_owner_key(owner_key),
    )

    if _use_supabase():
        try:
            _insert_supabase(record)
            return True
        except Exception:
            logger.exception("runtime block supabase write failed; keeping in-process record", extra={"gate": gate})

    try:
        _MEMORY_STORE.insert(record)
    except Exception:
        logger.exception("runtime block in-process write failed", extra={"gate": gate})
        return False
    return True


def list_blocks(owner_key: str | None, *, limit: int = DEFAULT_LIST_LIMIT) -> list[dict[str, Any]]:
    normalized = normalize_owner_key(owner_key)
    if normalized is None:
        return []
    bounded = max(1, min(limit, MAX_LIST_LIMIT))
    if _use_supabase():
        return _list_supabase(normalized, bounded)
    return _MEMORY_STORE.list_for_owner(normalized, bounded)


def reset_block_store() -> None:
    _MEMORY_STORE.clear()
