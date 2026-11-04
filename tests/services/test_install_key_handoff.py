from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.core.install_keys import InstallKeyRecord, InstallKeyRegistry
from app.persistencebootstrap import InMemoryPersistenceStore, SupabasePersistenceStore
import app.services.install_key_handoff as install_key_handoff
from app.services.install_key_handoff import (
    InstallKeyHandoffError,
    InstallKeyHandoffService,
    InstallKeySecretUnavailableError,
    InvalidInstallKeyClaimError,
    reset_install_key_handoff_service,
)

_OWNER_KEY = "buyer@ironclaw.test"
_PROGRAM = "openclaw"
_KEY_ID = "ik_handoff_test_001"
_RAW_KEY = "ic_install_openclaw_handoff_secret_123456"


@pytest.fixture(autouse=True)
def reset_handoff_state() -> Generator[None, None, None]:
    reset_install_key_handoff_service()
    yield
    reset_install_key_handoff_service()


def _build_service(
    *,
    record: InstallKeyRecord | None = None,
    encryption_secret: str = "test-install-key-encryption-secret",
) -> InstallKeyHandoffService:
    registry = MagicMock(spec=InstallKeyRegistry)
    registry.get_key_by_id.return_value = record
    return InstallKeyHandoffService(
        persistence_store=InMemoryPersistenceStore(fallback_enabled=False),
        install_key_registry=registry,
        encryption_secret=encryption_secret,
    )


def _make_record(*, active: bool = True) -> InstallKeyRecord:
    return InstallKeyRecord(
        key_id=_KEY_ID,
        owner_key=_OWNER_KEY,
        subscription_id="sub_handoff_test",
        program=_PROGRAM,
        raw_key=_RAW_KEY,
        active=active,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
    )


def test_secret_is_encrypted_and_claim_can_only_be_redeemed_once() -> None:
    record = _make_record()
    service = _build_service(record=record)

    service.store_secret(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        install_key=_RAW_KEY,
    )

    stored_secret = install_key_handoff._MEMORY_SECRETS[record.key_id]
    assert _RAW_KEY.encode("utf-8") not in stored_secret.encrypted_key

    claim = service.issue_claim(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
    )
    assert not hasattr(claim, "expires_at")
    assert claim.claim_token not in repr(claim)

    redemption = service.redeem_claim(claim.claim_token)
    assert redemption.install_key == _RAW_KEY
    assert _RAW_KEY not in repr(redemption)
    with pytest.raises(InvalidInstallKeyClaimError):
        service.redeem_claim(claim.claim_token)


def test_new_record_and_secret_are_persisted_atomically() -> None:
    record = _make_record()
    client = MagicMock()
    client.rpc.return_value = True
    store = SupabasePersistenceStore(client=client)
    service = InstallKeyHandoffService(
        persistence_store=store,
        install_key_registry=MagicMock(spec=InstallKeyRegistry),
        encryption_secret="test-install-key-encryption-secret",
    )

    service.persist_new_record(record)

    client.rpc.assert_called_once()
    function_name, payload = client.rpc.call_args.args
    assert function_name == "issue_install_key_record_with_secret"
    assert payload["p_install_key_record"]["key_id"] == _KEY_ID
    assert "raw_key" not in payload["p_install_key_record"]
    assert _RAW_KEY not in str(payload)


def test_atomic_record_persistence_failure_is_reported() -> None:
    record = _make_record()
    client = MagicMock()
    client.rpc.return_value = False
    store = SupabasePersistenceStore(client=client)
    service = InstallKeyHandoffService(
        persistence_store=store,
        install_key_registry=MagicMock(spec=InstallKeyRegistry),
        encryption_secret="test-install-key-encryption-secret",
    )

    with pytest.raises(InstallKeySecretUnavailableError, match="stored atomically"):
        service.persist_new_record(record)


def test_new_claim_invalidates_previous_claim() -> None:
    record = _make_record()
    service = _build_service(record=record)
    service.store_secret(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        install_key=_RAW_KEY,
    )

    first_claim = service.issue_claim(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
    )
    second_claim = service.issue_claim(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
    )

    with pytest.raises(InvalidInstallKeyClaimError):
        service.redeem_claim(first_claim.claim_token)
    assert service.redeem_claim(second_claim.claim_token).install_key == _RAW_KEY


def test_claim_has_no_expiry_and_stays_redeemable_until_used() -> None:
    record = _make_record()
    service = _build_service(record=record)
    service.store_secret(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        install_key=_RAW_KEY,
    )
    claim = service.issue_claim(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
    )

    assert not hasattr(install_key_handoff._MEMORY_SECRETS[record.key_id], "claim_expires_at")
    assert service.redeem_claim(claim.claim_token).install_key == _RAW_KEY


def test_secret_cannot_be_stored_for_an_unsupported_runtime() -> None:
    service = _build_service()

    with pytest.raises(ValueError, match="Unsupported runtime"):
        service.store_secret(
            key_id=_KEY_ID,
            owner_key=_OWNER_KEY,
            program="security_guardian",
            install_key="ic_install_security_guardian_secret_123456",
        )


def test_claim_requires_an_active_paid_record_and_recoverable_secret() -> None:
    inactive_service = _build_service(record=_make_record(active=False))

    with pytest.raises(InstallKeySecretUnavailableError, match="active paid install key"):
        inactive_service.issue_claim(
            key_id=_KEY_ID,
            owner_key=_OWNER_KEY,
            program=_PROGRAM,
        )

    service = _build_service(record=_make_record())
    with pytest.raises(InstallKeySecretUnavailableError, match="no recoverable secret"):
        service.issue_claim(
            key_id=_KEY_ID,
            owner_key=_OWNER_KEY,
            program=_PROGRAM,
        )


def test_memory_storage_is_rejected_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _build_service(record=_make_record())
    monkeypatch.setattr(
        install_key_handoff,
        "get_settings",
        lambda: SimpleNamespace(environment="production"),
    )

    with pytest.raises(InstallKeyHandoffError, match="Durable install-key handoff storage"):
        service.store_secret(
            key_id=_KEY_ID,
            owner_key=_OWNER_KEY,
            program=_PROGRAM,
            install_key=_RAW_KEY,
        )


def test_saved_command_is_encrypted_and_survives_until_redeemed() -> None:
    record = _make_record()
    service = _build_service(record=record)
    service.store_secret(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        install_key=_RAW_KEY,
    )
    claim = service.issue_claim(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
    )
    command = f"python -m ironclaw_installer redeem --program openclaw --claim-token {claim.claim_token}"

    service.save_command(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        command=command,
    )

    stored_secret = install_key_handoff._MEMORY_SECRETS[record.key_id]
    assert command.encode("utf-8") not in stored_secret.encrypted_command

    saved = service.get_saved_commands(owner_key=record.owner_key)
    assert set(saved) == {_PROGRAM}
    assert saved[_PROGRAM].command == command
    assert saved[_PROGRAM].key_id == record.key_id
    assert saved[_PROGRAM].claimed is False

    service.redeem_claim(claim.claim_token)
    assert service.get_saved_commands(owner_key=record.owner_key)[_PROGRAM].claimed is True


def test_saved_commands_are_scoped_to_the_owner() -> None:
    record = _make_record()
    service = _build_service(record=record)
    service.store_secret(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        install_key=_RAW_KEY,
    )
    service.save_command(
        key_id=record.key_id,
        owner_key=record.owner_key,
        program=record.program,
        command="python -m ironclaw_installer redeem --program openclaw --claim-token ic_claim_x",
    )

    assert service.get_saved_commands(owner_key="someone-else@ironclaw.test") == {}


def test_save_command_requires_recoverable_secret_and_non_empty_command() -> None:
    service = _build_service(record=_make_record())

    with pytest.raises(InstallKeySecretUnavailableError, match="No recoverable install key"):
        service.save_command(
            key_id=_KEY_ID,
            owner_key=_OWNER_KEY,
            program=_PROGRAM,
            command="python -m ironclaw_installer redeem --program openclaw --claim-token ic_claim_x",
        )

    service.store_secret(
        key_id=_KEY_ID,
        owner_key=_OWNER_KEY,
        program=_PROGRAM,
        install_key=_RAW_KEY,
    )
    with pytest.raises(ValueError, match="Install command is required"):
        service.save_command(
            key_id=_KEY_ID,
            owner_key=_OWNER_KEY,
            program=_PROGRAM,
            command="   ",
        )
