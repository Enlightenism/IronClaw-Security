from __future__ import annotations

import os

os.environ.setdefault("IRONCLAW_PERSISTENCE_MODE", "memory")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("IRONCLAW_API_KEY", "test-api-key")
os.environ.setdefault("AUTH_REQUIRED", "true")
os.environ.setdefault("IRONCLAW_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_SERVICE_ROLE_KEY", "")
os.environ.setdefault("SUPABASE_KEY", "")
os.environ.setdefault("SUPABASE_ANON_KEY", "")

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.core.install_keys import InstallKeyRecord
from app.services.install_key_provisioning import (
    InstallKeyIssued,
    InstallKeyProvisioningService,
)


def _make_install_key_record(
    *,
    owner_key: str,
    subscription_id: str,
    program: str,
    key_id: str,
    raw_key: str | None = None,
    active: bool = True,
    label: str = "test",
) -> InstallKeyRecord:
    resolved_raw_key = raw_key or ("ic_install_openclaw_test_secret_123456" if program == "openclaw" else "ic_install_claude_code_test_secret_abcdef")
    return InstallKeyRecord(
        key_id=key_id,
        owner_key=owner_key,
        subscription_id=subscription_id,
        program=program,  # type: ignore[arg-type]
        raw_key=resolved_raw_key,
        raw_key_hash=f"hash_{key_id}",
        masked_key=f"{resolved_raw_key[:25]}...{resolved_raw_key[-4:]}",
        label=label,
        active=active,
        units_consumed=0,
        metadata={"source": "test"},
    )


@pytest.fixture()
def service_components() -> tuple[InstallKeyProvisioningService, MagicMock, MagicMock, MagicMock]:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    install_key_registry.get_keys_for_owner.return_value = []

    wallet_registry = MagicMock()
    wallet_registry.get_or_create_wallet.return_value = SimpleNamespace(owner_key="buyer@ironclaw.test")

    service = InstallKeyProvisioningService(
        install_key_registry=install_key_registry,
        wallet_registry=wallet_registry,
        billing_registry=billing_registry,
    )
    return service, install_key_registry, wallet_registry, billing_registry


# ---------------------------------------------------------------------------
# resolve_owner_key
# ---------------------------------------------------------------------------


def test_resolve_owner_key_prefer_org_context_when_org_key_type_present() -> None:
    service = InstallKeyProvisioningService()
    auth_ctx = SimpleNamespace(key_type="org", org_id="org-42")
    resolved = service.resolve_owner_key(auth_ctx=auth_ctx, buyer_email="buyer@ironclaw.test")
    assert resolved == "ic_org_org-42"


def test_resolve_owner_key_falls_back_to_buyer_email_for_personal_context() -> None:
    service = InstallKeyProvisioningService()
    auth_ctx = SimpleNamespace(key_type="personal", org_id=None)
    resolved = service.resolve_owner_key(auth_ctx=auth_ctx, buyer_email=" Buyer@IRONCLAW.TEST ")
    assert resolved == "buyer@ironclaw.test"


def test_resolve_owner_key_uses_org_id_without_auth_ctx() -> None:
    service = InstallKeyProvisioningService()
    resolved = service.resolve_owner_key(buyer_email="buyer@ironclaw.test", org_id="org-9")
    assert resolved == "ic_org_org-9"


# ---------------------------------------------------------------------------
# ensure_entitled_owner / wallet creation guardrails
# ---------------------------------------------------------------------------


def test_ensure_entitled_owner_raises_when_subscription_missing() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = False

    service = InstallKeyProvisioningService(billing_registry=billing_registry)
    with pytest.raises(ValueError, match="no active subscription"):
        service.ensure_entitled_owner("buyer@ironclaw.test")


def test_ensure_wallet_calls_wallet_registry_with_normalized_owner() -> None:
    wallet_registry = MagicMock()
    wallet_registry.get_or_create_wallet.return_value = object()

    service = InstallKeyProvisioningService(wallet_registry=wallet_registry, billing_registry=MagicMock())
    service.ensure_wallet(" Buyer@IRONCLAW.TEST ")
    wallet_registry.get_or_create_wallet.assert_called_once_with("buyer@ironclaw.test", metadata={})


# ---------------------------------------------------------------------------
# provision_for_program
# ---------------------------------------------------------------------------


def test_provision_for_program_generates_key_and_returns_single_use_raw_key(service_components: tuple[InstallKeyProvisioningService, MagicMock, MagicMock, MagicMock]) -> None:
    service, install_key_registry, wallet_registry, billing_registry = service_components
    record = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_open_001",
        raw_key="ic_install_openclaw_secret_123456",
    )
    install_key_registry.generate_install_key.return_value = record

    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        source="purchase",
        label="auto-provisioned",
        metadata={"customer_id": "cus_123"},
    )

    assert isinstance(issued, InstallKeyIssued)
    assert issued.record.program == "openclaw"
    assert issued.raw_key.startswith("ic_install_openclaw_")
    assert issued.record.key_id == "ik_open_001"
    wallet_registry.get_or_create_wallet.assert_called()
    billing_registry.has_active_subscription.assert_called_with("buyer@ironclaw.test")

    install_key_registry.generate_install_key.assert_called_once()
    kwargs = install_key_registry.generate_install_key.call_args.kwargs
    assert kwargs["owner_key"] == "buyer@ironclaw.test"
    assert kwargs["subscription_id"] == "sub_123"
    assert kwargs["program"] == "openclaw"
    assert kwargs["label"] == "auto-provisioned"
    assert kwargs["metadata"]["customer_id"] == "cus_123"
    assert kwargs["metadata"]["source"] == "purchase"


def test_provision_for_program_reuses_existing_active_key_without_duplicate_generation(service_components: tuple[InstallKeyProvisioningService, MagicMock, MagicMock, MagicMock]) -> None:
    service, install_key_registry, _, _ = service_components
    existing = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_existing_001",
        raw_key="ic_install_openclaw_existing_secret_777",
    )
    install_key_registry.get_keys_for_owner.return_value = [existing]

    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
    )

    assert issued.raw_key == ""
    assert issued.record.key_id == "ik_existing_001"
    install_key_registry.generate_install_key.assert_not_called()


def test_provision_for_program_rejects_unknown_program() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    with pytest.raises(ValueError, match="Unsupported install key program"):
        service.provision_for_program(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program="gpt-4o",
        )


# ---------------------------------------------------------------------------
# provision_for_purchase
# ---------------------------------------------------------------------------


def test_provision_for_purchase_generates_both_supported_programs() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program="openclaw",
            key_id="ik_open_001",
            raw_key="ic_install_openclaw_purchase_secret_1",
        ),
        _make_install_key_record(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program="claude_code",
            key_id="ik_claude_001",
            raw_key="ic_install_claude_code_purchase_secret_2",
        ),
    ]

    wallet_registry = MagicMock()
    wallet_registry.get_or_create_wallet.return_value = object()

    service = InstallKeyProvisioningService(
        install_key_registry=install_key_registry,
        wallet_registry=wallet_registry,
        billing_registry=billing_registry,
    )

    results = service.provision_for_purchase(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        customer_id="cus_123",
        source="purchase",
    )

    assert set(results.keys()) == {"openclaw", "claude_code"}
    assert results["openclaw"].raw_key.startswith("ic_install_openclaw_")
    assert results["claude_code"].raw_key.startswith("ic_install_claude_code_")
    assert install_key_registry.generate_install_key.call_count == 2


def test_provision_for_purchase_uses_org_owner_resolution_when_auth_ctx_is_org() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    install_key_registry.generate_install_key.side_effect = [
        _make_install_key_record(
            owner_key="ic_org_org-42",
            subscription_id="sub_123",
            program="openclaw",
            key_id="ik_open_001",
            raw_key="ic_install_openclaw_org_secret_1",
        ),
        _make_install_key_record(
            owner_key="ic_org_org-42",
            subscription_id="sub_123",
            program="claude_code",
            key_id="ik_claude_001",
            raw_key="ic_install_claude_code_org_secret_2",
        ),
    ]

    wallet_registry = MagicMock()
    wallet_registry.get_or_create_wallet.return_value = object()

    service = InstallKeyProvisioningService(
        install_key_registry=install_key_registry,
        wallet_registry=wallet_registry,
        billing_registry=billing_registry,
    )

    auth_ctx = SimpleNamespace(key_type="org", org_id="org-42")

    service.provision_for_purchase(
        subscription_id="sub_123",
        buyer_email="buyer@ironclaw.test",
        auth_ctx=auth_ctx,
        customer_id="cus_123",
    )

    billing_registry.has_active_subscription.assert_any_call("ic_org_org-42")


def test_provision_for_purchase_requires_owner_or_identity_context() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    with pytest.raises(ValueError, match="Either owner_key or buyer_email/org_id/auth_ctx"):
        service.provision_for_purchase(subscription_id="sub_123")


# ---------------------------------------------------------------------------
# issue_install_key
# ---------------------------------------------------------------------------


def test_issue_install_key_calls_same_provisioning_path() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    record = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_open_manual",
        raw_key="ic_install_openclaw_manual_secret_abc",
    )
    install_key_registry.generate_install_key.return_value = record

    wallet_registry = MagicMock()
    wallet_registry.get_or_create_wallet.return_value = object()

    service = InstallKeyProvisioningService(
        install_key_registry=install_key_registry,
        wallet_registry=wallet_registry,
        billing_registry=billing_registry,
    )

    issued = service.issue_install_key(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        source="manual",
        label="manual-issued",
    )

    assert isinstance(issued, InstallKeyIssued)
    assert issued.record.key_id == "ik_open_manual"
    assert issued.raw_key.startswith("ic_install_openclaw_")
    install_key_registry.generate_install_key.assert_called_once()


# ---------------------------------------------------------------------------
# public API / singleton
# ---------------------------------------------------------------------------


def test_provision_install_key_service_returns_singleton() -> None:
    from app.services.install_key_provisioning import provision_install_key_service

    first = provision_install_key_service()
    second = provision_install_key_service()
    assert first is second
