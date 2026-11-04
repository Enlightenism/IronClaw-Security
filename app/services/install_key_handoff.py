from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import secrets
from threading import RLock
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.install_key_formats import RUNTIME_INSTALL_KEY_PROGRAMS, InstallKeyFormatRegistry
from app.core.install_keys import InstallKeyRecord, InstallKeyRegistry, get_install_key_registry
from app.core.settings import get_settings
from app.persistencebootstrap import InMemoryPersistenceStore, SupabasePersistenceStore, get_persistence_store

_KEY_VERSION = "v1"
_MEMORY_LOCK = RLock()


@dataclass(slots=True)
class _MemorySecret:
    owner_key: str
    program: str
    encrypted_key: bytes
    claim_token_hash: str | None = None
    claimed: bool = False
    encrypted_command: bytes | None = None


_MEMORY_SECRETS: dict[str, _MemorySecret] = {}


@dataclass(frozen=True, slots=True)
class InstallKeyClaim:
    key_id: str
    owner_key: str
    program: str
    claim_token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class InstallKeyRedemption:
    key_id: str
    owner_key: str
    program: str
    install_key: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class InstallKeySavedCommand:
    key_id: str
    program: str
    command: str = field(repr=False)
    claimed: bool


class InstallKeyHandoffError(RuntimeError):
    pass


class InstallKeySecretUnavailableError(InstallKeyHandoffError):
    pass


class InvalidInstallKeyClaimError(InstallKeyHandoffError):
    pass


class InstallKeyHandoffService:
    def __init__(
        self,
        *,
        persistence_store: InMemoryPersistenceStore | SupabasePersistenceStore | None = None,
        install_key_registry: InstallKeyRegistry | None = None,
        encryption_secret: str | None = None,
    ) -> None:
        self._persistence_store = persistence_store
        self._install_key_registry = install_key_registry or get_install_key_registry()
        self._encryption_secret = encryption_secret

    def _store(self) -> InMemoryPersistenceStore | SupabasePersistenceStore:
        if self._persistence_store is None:
            self._persistence_store = get_persistence_store(allow_fallback=False)
        if isinstance(self._persistence_store, InMemoryPersistenceStore):
            if get_settings().environment.strip().lower() in {"production", "prod"}:
                raise InstallKeyHandoffError("Durable install-key handoff storage is required in production.")
        elif not isinstance(self._persistence_store, SupabasePersistenceStore):
            raise TypeError("Unsupported persistence store for install-key handoff.")
        return self._persistence_store

    def _fernet(self) -> Fernet:
        secret = self._encryption_secret or get_settings().secret_key
        if not secret.strip():
            raise InstallKeyHandoffError("Install-key encryption is unavailable because the server secret is not configured.")
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"ironclaw-install-key-secret-v1",
            info=b"private-install-key-secrets",
        ).derive(secret.encode("utf-8"))
        return Fernet(base64.urlsafe_b64encode(key))

    @staticmethod
    def _normalize_identity(key_id: str, owner_key: str, program: str) -> tuple[str, str, str]:
        normalized_key_id = str(key_id).strip()
        normalized_owner = str(owner_key).strip().lower()
        normalized_program = InstallKeyFormatRegistry.normalize_program(program)
        if not normalized_key_id or not normalized_owner:
            raise ValueError("key_id and owner_key are required for install-key handoff.")
        if normalized_program not in RUNTIME_INSTALL_KEY_PROGRAMS:
            raise ValueError(f"Unsupported runtime program for install-key handoff: {program!r}")
        return normalized_key_id, normalized_owner, normalized_program

    @staticmethod
    def _claim_hash(claim_token: str) -> str:
        candidate = str(claim_token).strip()
        if not candidate.startswith("ic_claim_") or len(candidate) > 256:
            raise InvalidInstallKeyClaimError("Install claim is invalid, expired, or already redeemed.")
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest()

    @staticmethod
    def _rpc_boolean(result: Any, operation: str) -> bool:
        if isinstance(result, bool):
            return result
        if isinstance(result, list) and len(result) == 1:
            return InstallKeyHandoffService._rpc_boolean(result[0], operation)
        if isinstance(result, dict) and len(result) == 1:
            return InstallKeyHandoffService._rpc_boolean(next(iter(result.values())), operation)
        raise InstallKeyHandoffError(f"Install-key handoff storage returned an invalid {operation} response.")

    @staticmethod
    def _rpc_row(result: Any) -> dict[str, Any] | None:
        if result is None or result == []:
            return None
        if isinstance(result, list):
            if len(result) != 1:
                raise InstallKeyHandoffError("Install-key claim redemption returned an invalid response.")
            result = result[0]
        if not isinstance(result, dict):
            raise InstallKeyHandoffError("Install-key claim redemption returned an invalid response.")
        return result

    def store_secret(
        self,
        *,
        key_id: str,
        owner_key: str,
        program: str,
        install_key: str,
    ) -> None:
        normalized_key_id, normalized_owner, normalized_program = self._normalize_identity(
            key_id,
            owner_key,
            program,
        )
        encrypted_key = self._encrypt_key(normalized_program, install_key)
        store = self._store()
        if isinstance(store, InMemoryPersistenceStore):
            with _MEMORY_LOCK:
                existing = _MEMORY_SECRETS.get(normalized_key_id)
                if existing is not None and (existing.owner_key != normalized_owner or existing.program != normalized_program):
                    raise InstallKeyHandoffError("Install-key secret identity does not match the stored record.")
                _MEMORY_SECRETS[normalized_key_id] = _MemorySecret(
                    owner_key=normalized_owner,
                    program=normalized_program,
                    encrypted_key=encrypted_key,
                )
            return

        stored = store.rpc(
            "store_install_key_secret",
            {
                "p_key_id": normalized_key_id,
                "p_owner_key": normalized_owner,
                "p_program": normalized_program,
                "p_encrypted_key_base64": base64.b64encode(encrypted_key).decode("ascii"),
                "p_key_version": _KEY_VERSION,
            },
            schema="public",
        )
        if not self._rpc_boolean(stored, "secret storage"):
            raise InstallKeySecretUnavailableError("Install-key secret could not be stored for secure delivery.")

    def persist_new_record(self, record: InstallKeyRecord) -> None:
        key_id, owner_key, program = self._normalize_identity(
            record.key_id,
            record.owner_key,
            record.program,
        )
        if not record.active or record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
            raise InstallKeySecretUnavailableError("Only active paid install keys can be securely persisted.")

        store = self._store()
        if isinstance(store, InMemoryPersistenceStore):
            self.store_secret(
                key_id=key_id,
                owner_key=owner_key,
                program=program,
                install_key=record.raw_key,
            )
            return

        encrypted_key = self._encrypt_key(program, record.raw_key)
        persisted = store.rpc(
            "issue_install_key_record_with_secret",
            {
                "p_install_key_record": record.to_db_row(),
                "p_encrypted_key_base64": base64.b64encode(encrypted_key).decode("ascii"),
                "p_key_version": _KEY_VERSION,
            },
            schema="public",
        )
        if not self._rpc_boolean(persisted, "record and secret persistence"):
            raise InstallKeySecretUnavailableError("Install-key record and secret could not be stored atomically for secure delivery.")

    def save_command(self, *, key_id: str, owner_key: str, program: str, command: str) -> None:
        normalized_key_id, normalized_owner, normalized_program = self._normalize_identity(
            key_id,
            owner_key,
            program,
        )
        normalized_command = str(command).strip()
        if not normalized_command:
            raise ValueError("Install command is required for saving.")
        encrypted_command = self._fernet().encrypt(normalized_command.encode("utf-8"))

        store = self._store()
        if isinstance(store, InMemoryPersistenceStore):
            with _MEMORY_LOCK:
                secret = _MEMORY_SECRETS.get(normalized_key_id)
                if secret is None or secret.owner_key != normalized_owner or secret.program != normalized_program:
                    raise InstallKeySecretUnavailableError("No recoverable install key is available to save this command.")
                secret.encrypted_command = encrypted_command
            return

        stored = store.rpc(
            "store_install_key_command",
            {
                "p_key_id": normalized_key_id,
                "p_owner_key": normalized_owner,
                "p_program": normalized_program,
                "p_encrypted_command_base64": base64.b64encode(encrypted_command).decode("ascii"),
                "p_key_version": _KEY_VERSION,
            },
            schema="public",
        )
        if not self._rpc_boolean(stored, "command storage"):
            raise InstallKeySecretUnavailableError("Install command could not be saved for this key.")

    def get_saved_commands(self, *, owner_key: str) -> dict[str, InstallKeySavedCommand]:
        normalized_owner = str(owner_key).strip().lower()
        if not normalized_owner:
            raise ValueError("owner_key is required to load saved install commands.")

        store = self._store()
        rows: list[dict[str, Any]] = []
        if isinstance(store, InMemoryPersistenceStore):
            with _MEMORY_LOCK:
                for key_id, secret in _MEMORY_SECRETS.items():
                    if secret.owner_key != normalized_owner or secret.encrypted_command is None:
                        continue
                    rows.append(
                        {
                            "key_id": key_id,
                            "program": secret.program,
                            "key_version": _KEY_VERSION,
                            "encrypted_command_base64": base64.b64encode(secret.encrypted_command).decode("ascii"),
                            "claimed": secret.claimed,
                        }
                    )
        else:
            result = store.rpc(
                "get_install_key_commands",
                {"p_owner_key": normalized_owner},
                schema="public",
            )
            if result is None:
                rows = []
            elif isinstance(result, list) and all(isinstance(row, dict) for row in result):
                rows = result
            else:
                raise InstallKeyHandoffError("Install-key command storage returned an invalid response.")

        saved: dict[str, InstallKeySavedCommand] = {}
        for row in rows:
            try:
                key_id, _, program = self._normalize_identity(
                    str(row["key_id"]),
                    normalized_owner,
                    str(row["program"]),
                )
                if str(row["key_version"]) != _KEY_VERSION:
                    raise InstallKeyHandoffError("Saved install command uses an unsupported encryption version.")
                encrypted_command = base64.b64decode(str(row["encrypted_command_base64"]), validate=True)
                command = self._fernet().decrypt(encrypted_command).decode("utf-8")
            except (KeyError, ValueError, InvalidToken) as exc:
                raise InstallKeyHandoffError("Saved install command could not be decrypted.") from exc
            saved[program] = InstallKeySavedCommand(
                key_id=key_id,
                program=program,
                command=command,
                claimed=bool(row["claimed"]),
            )
        return saved

    def _encrypt_key(self, program: str, install_key: str) -> bytes:
        normalized_key = str(install_key).strip()
        spec = InstallKeyFormatRegistry.get_spec(program)
        if not spec.matches_key(normalized_key):
            raise ValueError("Install key does not match the canonical runtime format.")
        return self._fernet().encrypt(normalized_key.encode("utf-8"))

    def issue_claim(self, *, key_id: str, owner_key: str, program: str) -> InstallKeyClaim:
        normalized_key_id, normalized_owner, normalized_program = self._normalize_identity(
            key_id,
            owner_key,
            program,
        )
        record = self._install_key_registry.get_key_by_id(normalized_key_id)
        if record is None or record.owner_key != normalized_owner or record.program != normalized_program or not record.active or record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
            raise InstallKeySecretUnavailableError("No active paid install key is available for this owner and runtime.")

        claim_token = f"ic_claim_{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(claim_token.encode("utf-8")).hexdigest()

        store = self._store()
        if isinstance(store, InMemoryPersistenceStore):
            with _MEMORY_LOCK:
                secret = _MEMORY_SECRETS.get(normalized_key_id)
                if secret is None or secret.owner_key != normalized_owner or secret.program != normalized_program:
                    raise InstallKeySecretUnavailableError("This install key has no recoverable secret; it must be reissued before installation.")
                secret.claim_token_hash = token_hash
                secret.claimed = False
        else:
            issued = store.rpc(
                "issue_install_key_claim",
                {
                    "p_key_id": normalized_key_id,
                    "p_owner_key": normalized_owner,
                    "p_program": normalized_program,
                    "p_claim_token_hash": token_hash,
                    "p_claim_expires_at": None,
                },
                schema="public",
            )
            if not self._rpc_boolean(issued, "claim issuance"):
                raise InstallKeySecretUnavailableError("This install key has no recoverable secret; it must be reissued before installation.")

        return InstallKeyClaim(
            key_id=normalized_key_id,
            owner_key=normalized_owner,
            program=normalized_program,
            claim_token=claim_token,
        )

    def redeem_claim(self, claim_token: str) -> InstallKeyRedemption:
        token_hash = self._claim_hash(claim_token)
        store = self._store()
        if isinstance(store, InMemoryPersistenceStore):
            with _MEMORY_LOCK:
                match = next(
                    ((key_id, secret) for key_id, secret in _MEMORY_SECRETS.items() if secret.claim_token_hash == token_hash),
                    None,
                )
                if match is None:
                    raise InvalidInstallKeyClaimError("Install claim is invalid or already redeemed.")
                key_id, secret = match
                secret.claim_token_hash = None
                secret.claimed = True
                row = {
                    "key_id": key_id,
                    "owner_key": secret.owner_key,
                    "program": secret.program,
                    "key_version": _KEY_VERSION,
                    "encrypted_key_base64": base64.b64encode(secret.encrypted_key).decode("ascii"),
                }
        else:
            result = store.rpc(
                "redeem_install_key_claim",
                {"p_claim_token_hash": token_hash},
                schema="public",
            )
            row = self._rpc_row(result)
            if row is None:
                raise InvalidInstallKeyClaimError("Install claim is invalid, expired, or already redeemed.")

        try:
            key_id, owner_key, program = self._normalize_identity(
                str(row["key_id"]),
                str(row["owner_key"]),
                str(row["program"]),
            )
            if str(row["key_version"]) != _KEY_VERSION:
                raise InstallKeyHandoffError("Install-key secret uses an unsupported encryption version.")
            encrypted_key = base64.b64decode(str(row["encrypted_key_base64"]), validate=True)
            install_key = self._fernet().decrypt(encrypted_key).decode("utf-8")
        except (KeyError, ValueError, InvalidToken) as exc:
            raise InstallKeyHandoffError("Install-key claim could not be decrypted.") from exc

        spec = InstallKeyFormatRegistry.get_spec(program)
        if not spec.matches_key(install_key):
            raise InstallKeyHandoffError("Decrypted install key does not match the canonical runtime format.")

        record = self._install_key_registry.get_key_by_id(key_id)
        if record is None or record.owner_key != owner_key or record.program != program or not record.active or record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
            raise InvalidInstallKeyClaimError("Install claim is invalid, expired, or already redeemed.")

        return InstallKeyRedemption(
            key_id=key_id,
            owner_key=owner_key,
            program=program,
            install_key=install_key,
        )


_install_key_handoff_service: InstallKeyHandoffService | None = None


def get_install_key_handoff_service() -> InstallKeyHandoffService:
    global _install_key_handoff_service
    if _install_key_handoff_service is None:
        _install_key_handoff_service = InstallKeyHandoffService()
    return _install_key_handoff_service


def reset_install_key_handoff_service() -> None:
    global _install_key_handoff_service
    with _MEMORY_LOCK:
        _MEMORY_SECRETS.clear()
    _install_key_handoff_service = None
