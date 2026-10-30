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
from app.services.install_key_handoff import reset_install_key_handoff_service
from app.services.install_key_provisioning import InstallKeyIssued, InstallKeyProvisioningService


@pytest.fixture(autouse=True)
def reset_install_key_handoffs() -> None:
    reset_install_key_handoff_service()


def _make_install_key_record(
    *,
    owner_key: str,
    subscription_id: str,
    program: str,
    key_id: str,
    raw_key: str | None = None,
    active: bool = True,
    label: str = "test",
    issued_after_payment: bool = True,
    payment_status: str = "paid",
    entitlements_status: str = "active",
    purchase_reference: str | None = None,
    checkout_session_id: str | None = None,
) -> InstallKeyRecord:
    default_keys = {
        "openclaw": "ic_install_openclaw_test_secret_123456",
        "claude_code": "ic_install_claude_code_test_secret_abcdef",
        "cursor": "ic_install_cursor_test_secret_cursor",
        "goose": "ic_install_goose_test_secret_goose",
        "gemini_cli": "ic_install_gemini_cli_test_secret_gemini",
        "copilot": "ic_install_copilot_test_secret_copilot",
        "hermes": "ic_install_hermes_test_secret_hermes",
        "security_guardian": "ic_install_security_guardian_test_secret_guardian",
    }
    resolved_raw_key = raw_key or default_keys.get(program, "ic_install_openclaw_test_secret_123456")
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
        issued_after_payment=issued_after_payment,
        payment_status=payment_status,
        entitlements_status=entitlements_status,
        purchase_reference=purchase_reference or subscription_id,
        checkout_session_id=checkout_session_id or subscription_id,
        units_consumed=0,
        metadata={"source": "test"},
    )


def _make_service(*, active_subscription: bool = True, owner_key: str = "buyer@ironclaw.test", existing_records: list[InstallKeyRecord] | None = None) -> tuple[InstallKeyProvisioningService, MagicMock, MagicMock, MagicMock]:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = active_subscription

    install_key_registry = MagicMock()
    install_key_registry.get_keys_for_owner.return_value = list(existing_records or [])
    wallet_registry = MagicMock()
    wallet_registry.get_or_create_wallet.return_value = SimpleNamespace(owner_key=owner_key)

    service = InstallKeyProvisioningService(
        install_key_registry=install_key_registry,
        wallet_registry=wallet_registry,
        billing_registry=billing_registry,
    )
    return service, install_key_registry, wallet_registry, billing_registry


def test_resolve_owner_key_normalizes_personal_and_org_context() -> None:
    service = InstallKeyProvisioningService()
    assert service.resolve_owner_key(auth_ctx=SimpleNamespace(key_type="personal", org_id=None), buyer_email=" Buyer@IRONCLAW.TEST ") == "buyer@ironclaw.test"
    assert service.resolve_owner_key(auth_ctx=SimpleNamespace(key_type="org", org_id="org-42"), buyer_email="buyer@ironclaw.test") == "ic_org_org-42"


def test_ensure_entitled_owner_requires_active_subscription() -> None:
    service, _, _, _ = _make_service(active_subscription=False)
    with pytest.raises(ValueError, match="no active subscription"):
        service.ensure_entitled_owner("buyer@ironclaw.test")


def test_ensure_wallet_creates_wallet_for_normalized_owner_key() -> None:
    service, _, wallet_registry, _ = _make_service()

    wallet = service.ensure_wallet(" Buyer@IRONCLAW.TEST ", metadata={"source": "purchase"})

    assert wallet is wallet_registry.get_or_create_wallet.return_value
    wallet_registry.get_or_create_wallet.assert_called_once_with("buyer@ironclaw.test", metadata={"source": "purchase"})


def test_provision_for_program_issues_paid_active_key_with_stripe_metadata() -> None:
    service, install_key_registry, wallet_registry, billing_registry = _make_service()
    record = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_open_001",
        raw_key="ic_install_openclaw_paid_secret_123456",
    )
    install_key_registry.generate_for_paid_customer.return_value = record

    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        source="stripe.checkout",
        label="auto-provisioned",
        metadata={
            "source": "stale-source",
            "customer_id": "cus_123",
            "purchase_reference": "placeholder_purchase",
            "checkout_session_id": "placeholder_checkout",
        },
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        checkout_session_id="cs_real_123",
        purchase_reference="pi_real_456",
    )

    assert isinstance(issued, InstallKeyIssued)
    assert issued.record.key_id == "ik_open_001"
    assert issued.raw_key == ""
    assert record.raw_key == ""
    assert "raw_key" not in issued.delivery_payload()
    wallet_registry.get_or_create_wallet.assert_called()
    billing_registry.has_active_subscription.assert_called_with("buyer@ironclaw.test")

    kwargs = install_key_registry.generate_for_paid_customer.call_args.kwargs
    assert kwargs["owner_key"] == "buyer@ironclaw.test"
    assert kwargs["program"] == "openclaw"
    assert kwargs["payment_status"] == "paid"
    assert kwargs["entitlements_status"] == "active"
    assert kwargs["issued_after_payment"] is True
    assert kwargs["checkout_session_id"] == "cs_real_123"
    assert kwargs["purchase_reference"] == "pi_real_456"
    assert kwargs["metadata"]["source"] == "stripe.checkout"
    assert kwargs["metadata"]["customer_id"] == "cus_123"
    assert kwargs["metadata"]["checkout_session_id"] == "cs_real_123"
    assert kwargs["metadata"]["purchase_reference"] == "pi_real_456"
    assert kwargs["secure_record_persistor"] == service._handoff_service.persist_new_record


def test_provision_for_program_reuses_active_key_without_duplicate_generation() -> None:
    existing = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_existing_001",
        raw_key="ic_install_openclaw_existing_secret_777",
    )
    service, install_key_registry, _, _ = _make_service(existing_records=[existing])

    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
    )

    assert issued.raw_key == ""
    assert issued.record.key_id == "ik_existing_001"
    install_key_registry.generate_for_paid_customer.assert_not_called()


def test_provision_for_purchase_issues_program_specific_keys_with_stripe_refs() -> None:
    service, install_key_registry, _, _ = _make_service()
    records = [
        _make_install_key_record(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_432",
            program=program,
            key_id=f"ik_{program}_001",
            raw_key=f"ic_install_{program}_issue_secret_123",
        )
        for program in ("openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes")
    ]
    install_key_registry.generate_for_paid_customer.side_effect = records

    results = service.provision_for_purchase(
        buyer_email=" Buyer@IRONCLAW.TEST ",
        subscription_id="sub_432",
        customer_id="cus_999",
        checkout_session_id="cs_999",
        purchase_reference="purch_999",
        source="stripe.checkout",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
    )

    assert set(results) == {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes"}
    assert results["openclaw"].record.key_id == "ik_openclaw_001"
    assert results["hermes"].record.key_id == "ik_hermes_001"
    first_call = install_key_registry.generate_for_paid_customer.call_args_list[0].kwargs
    assert first_call["metadata"]["customer_id"] == "cus_999"
    assert first_call["metadata"]["checkout_session_id"] == "cs_999"
    assert first_call["metadata"]["purchase_reference"] == "purch_999"
    assert first_call["metadata"]["source"] == "stripe.checkout"
    assert first_call["metadata"]["payment_status"] == "paid"
    assert first_call["metadata"]["entitlements_status"] == "active"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"payment_status": "pending", "entitlements_status": "not_active", "issued_after_payment": False}, "successful payment confirmation"),
        ({"payment_status": "paid", "entitlements_status": "not_active", "issued_after_payment": True}, "active paid entitlement"),
    ],
)
def test_provision_for_program_fail_closes_without_real_paid_entitlement(kwargs: dict[str, object], match: str) -> None:
    service, _, _, _ = _make_service()
    with pytest.raises(ValueError, match=match):
        service.provision_for_program(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program="openclaw",
            **kwargs,
        )


def test_resolve_owner_key_rejects_generic_platform_tokens() -> None:
    service = InstallKeyProvisioningService()
    with pytest.raises(ValueError, match="not valid install-key owners"):
        service.resolve_owner_key(auth_ctx=None, buyer_email="xoxb-abc123")


def test_provision_for_program_accepts_aliases_for_supported_runtimes() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    for alias, expected in {
        "github-copilot": "copilot",
        "gemini-cli": "gemini_cli",
        "cursor-agent": "cursor",
        "hermes-agent": "hermes",
        "goose-agent": "goose",
    }.items():
        service._install_key_registry.get_keys_for_owner.return_value = []
        service._install_key_registry.generate_for_paid_customer.return_value = _make_install_key_record(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program=expected,
            key_id=f"ik_alias_{expected}",
            raw_key=f"ic_install_{expected}_alias_secret",
        )

        issued = service.provision_for_program(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program=alias,
        )

        assert issued.record.program == expected
        assert issued.record.raw_key == ""
        assert issued.raw_key == ""


@pytest.mark.parametrize(
    ("program", "alias", "expected_prefix"),
    [
        ("cursor", "cursor-agent", "ic_install_cursor_"),
        ("goose", "goose-agent", "ic_install_goose_"),
        ("gemini_cli", "gemini-cli", "ic_install_gemini_cli_"),
        ("copilot", "github-copilot", "ic_install_copilot_"),
        ("hermes", "hermes-agent", "ic_install_hermes_"),
    ],
)
def test_provision_for_program_generates_modern_runtime_keys_only_after_paid_entitlement(program: str, alias: str, expected_prefix: str) -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )
    service._install_key_registry.get_keys_for_owner.return_value = []
    service._install_key_registry.generate_for_paid_customer.return_value = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program=program,
        key_id=f"ik_{program}_001",
        raw_key=f"{expected_prefix}runtime_secret_123",
    )

    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program=alias,
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
    )

    assert issued.record.program == program
    assert issued.record.raw_key == ""
    assert issued.raw_key == ""
    assert "raw_key" not in issued.delivery_payload()


def test_provision_for_program_rejects_hermes_when_payment_not_confirmed() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    with pytest.raises(ValueError, match="successful payment confirmation"):
        service.provision_for_program(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program="hermes",
            payment_status="pending",
            entitlements_status="active",
            issued_after_payment=True,
        )


def test_provision_for_program_rejects_security_guardian_runtime_issuance() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    for alias in ("security_guardian", "security-guardian", "securityguardian", "skill"):
        with pytest.raises(ValueError, match="Security Guardian.*connector|runtime install key"):
            service.provision_for_program(
                owner_key="buyer@ironclaw.test",
                subscription_id="sub_123",
                program=alias,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
            )


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


def test_provision_for_purchase_generates_all_supported_programs() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    install_key_registry.generate_for_paid_customer.side_effect = [
        _make_install_key_record(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program=program,
            key_id=f"ik_{program}_001",
            raw_key=f"ic_install_{program}_purchase_secret_1",
        )
        for program in (
            "openclaw",
            "claude_code",
            "cursor",
            "goose",
            "gemini_cli",
            "copilot",
            "hermes",
            "security_guardian",
        )
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

    expected_programs = {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes"}
    assert set(results.keys()) == expected_programs
    for program in expected_programs:
        assert results[program].raw_key == ""
        assert "raw_key" not in results[program].delivery_payload()
    assert "security_guardian" not in results
    assert install_key_registry.generate_for_paid_customer.call_count == 7


def test_provision_for_purchase_uses_org_owner_resolution_when_auth_ctx_is_org() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    install_key_registry.generate_for_paid_customer.side_effect = [
        _make_install_key_record(
            owner_key="ic_org_org-42",
            subscription_id="sub_123",
            program=program,
            key_id=f"ik_{program}_001",
            raw_key=f"ic_install_{program}_org_secret_1",
        )
        for program in (
            "openclaw",
            "claude_code",
            "cursor",
            "goose",
            "gemini_cli",
            "copilot",
            "hermes",
        )
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


def test_provision_for_purchase_omits_security_guardian_from_runtime_platform_enumeration() -> None:
    billing_registry = MagicMock()
    billing_registry.has_active_subscription.return_value = True

    install_key_registry = MagicMock()
    install_key_registry.generate_for_paid_customer.side_effect = [
        _make_install_key_record(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program=program,
            key_id=f"ik_{program}_001",
            raw_key=f"ic_install_{program}_purchase_secret_{index}",
        )
        for index, program in enumerate(
            (
                "openclaw",
                "claude_code",
                "cursor",
                "goose",
                "gemini_cli",
                "copilot",
                "hermes",
            ),
            start=1,
        )
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

    assert set(results.keys()) == {"openclaw", "claude_code", "cursor", "goose", "gemini_cli", "copilot", "hermes"}
    assert "security_guardian" not in results
    assert install_key_registry.generate_for_paid_customer.call_count == 7


def test_provision_for_purchase_rejects_generic_system_api_key_owner_fallback() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    auth_ctx = SimpleNamespace(key_type="api_key", org_id=None)
    with pytest.raises(ValueError, match="System API keys and generic auth tokens are not valid install-key owners"):
        service.resolve_owner_key(auth_ctx=auth_ctx, buyer_email="")


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
    install_key_registry.generate_for_paid_customer.return_value = record

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
    assert issued.raw_key == ""
    assert issued.record.raw_key == ""
    install_key_registry.generate_for_paid_customer.assert_called_once()


def test_provision_for_purchase_rejects_unconfirmed_payment() -> None:
    service = InstallKeyProvisioningService(
        install_key_registry=MagicMock(),
        wallet_registry=MagicMock(),
        billing_registry=MagicMock(has_active_subscription=MagicMock(return_value=True)),
    )

    with pytest.raises(ValueError, match="successful payment confirmation"):
        service.provision_for_purchase(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            payment_status="pending",
            payment_confirmed=False,
        )


def test_provision_for_program_reuses_valid_key_for_matching_checkout_reference() -> None:
    existing = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_existing_checkout_001",
        raw_key="ic_install_openclaw_existing_checkout_secret_9",
        purchase_reference="purchase_ref_abc",
        checkout_session_id="cs_abc",
    )
    service, install_key_registry, _, _ = _make_service(existing_records=[existing])

    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        checkout_session_id="cs_abc",
        purchase_reference="purchase_ref_other",
    )

    assert issued.record.key_id == "ik_existing_checkout_001"
    assert issued.raw_key == ""
    install_key_registry.generate_for_paid_customer.assert_not_called()


def test_provision_for_program_reuses_active_key_when_checkout_reference_differs() -> None:
    existing = _make_install_key_record(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        key_id="ik_existing_old_001",
        raw_key="ic_install_openclaw_existing_old_secret_9",
        purchase_reference="purchase_ref_old",
        checkout_session_id="cs_old",
    )
    service, install_key_registry, _, _ = _make_service(existing_records=[existing])
    issued = service.provision_for_program(
        owner_key="buyer@ironclaw.test",
        subscription_id="sub_123",
        program="openclaw",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        checkout_session_id="cs_new",
        purchase_reference="purchase_ref_new",
    )

    assert issued.record.key_id == "ik_existing_old_001"
    assert issued.raw_key == ""
    install_key_registry.generate_for_paid_customer.assert_not_called()


def test_issue_install_key_requires_payment_verification_gate() -> None:
    service, _, _, _ = _make_service()

    with pytest.raises(ValueError, match="successful payment confirmation"):
        service.issue_install_key(
            owner_key="buyer@ironclaw.test",
            subscription_id="sub_123",
            program="openclaw",
            payment_status="pending",
            entitlements_status="active",
            issued_after_payment=True,
        )


# ---------------------------------------------------------------------------
# public API / singleton
# ---------------------------------------------------------------------------


def test_provision_install_key_service_returns_singleton() -> None:
    from app.services.install_key_provisioning import provision_install_key_service

    first = provision_install_key_service()
    second = provision_install_key_service()
    assert first is second
