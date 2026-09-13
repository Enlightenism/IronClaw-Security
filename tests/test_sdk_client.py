from __future__ import annotations

import httpx
import pytest
import respx

import ironclaw_sdk
from ironclaw_sdk.client import IronclawClient
from ironclaw_sdk.exceptions import (
    IronclawAPIError,
    IronclawAuthError,
    IronclawInstallKeyInvalidError,
    IronclawInstallKeyOwnershipError,
    IronclawPaymentFailedError,
    IronclawPaymentPendingError,
    IronclawRetryExhausted,
    IronclawTimeoutError,
    IronclawUnsupportedInstallPlatformError,
)
from ironclaw_sdk.models import (
    BillingPackagePurchaseRequest,
    BillingPackagePurchaseResponse,
    BillingPackagePurchaseView,
    InstallKeySlotView,
    InstallKeysResponse,
    ScanRequest,
    ScanResponse,
)

_BASE = "http://testserver"
_KEY = "ironclaw-test-key-00000000"

_VALID_SCAN_RESPONSE = {
    "scan_id": "11111111-1111-1111-1111-111111111111",
    "verdict": "allow",
    "summary": "No threats detected.",
    "target_type": "text",
    "target_value": "hello world",
    "risk_score": 0,
    "matched_patterns": [],
    "risky_files": [],
    "checks_loaded": [],
    "failed_checks": [],
    "quarantine_reason": None,
    "review_status": "none",
    "untrusted": False,
    "sandbox_lane": "none",
    "timestamp": "2026-05-22T00:00:00Z",
    "max_severity": None,
    "primary_category": None,
    "explanation": None,
    "client_id": None,
}


def _make_client(api_key: str = _KEY, base_url: str = _BASE) -> IronclawClient:
    return IronclawClient(api_key=api_key, base_url=base_url, connect_timeout=2.0, read_timeout=2.0)


def _make_request() -> ScanRequest:
    return ScanRequest(target_type="text", target_value="hello world")


@pytest.mark.sdk
class TestApiKeyHeader:
    @respx.mock
    def test_api_key_header_present_on_every_request(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client()
        client.scan(_make_request())
        assert route.called
        sent_headers = route.calls[0].request.headers
        assert sent_headers.get("x-api-key") == _KEY

    def test_missing_api_key_raises_auth_error(self):
        with pytest.raises(IronclawAuthError):
            IronclawClient(api_key="", base_url=_BASE)

    def test_whitespace_api_key_raises_auth_error(self):
        with pytest.raises(IronclawAuthError):
            IronclawClient(api_key="   ", base_url=_BASE)


@pytest.mark.sdk
class TestAuthErrorHandling:
    @respx.mock
    def test_401_response_raises_auth_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(401, json={"detail": "Unauthorized"}))
        client = _make_client()
        with pytest.raises(IronclawAuthError) as exc_info:
            client.scan(_make_request())
        assert exc_info.value.status_code == 401

    @respx.mock
    def test_403_response_raises_auth_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(403, json={"detail": "Forbidden"}))
        client = _make_client()
        with pytest.raises(IronclawAuthError) as exc_info:
            client.scan(_make_request())
        assert exc_info.value.status_code == 403


@pytest.mark.sdk
class TestRetryBehavior:
    @respx.mock
    def test_500_triggers_retry_exactly_three_calls(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(500, text="error"))
        client = _make_client()
        with pytest.raises(IronclawRetryExhausted):
            client.scan(_make_request())
        assert route.call_count == 3

    @respx.mock
    def test_retry_exhausted_raises_ironclaw_retry_exhausted(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(503, text="unavailable"))
        client = _make_client()
        with pytest.raises(IronclawRetryExhausted) as exc_info:
            client.scan(_make_request())
        assert exc_info.value.attempts == 3

    @respx.mock
    def test_retry_after_header_respected(self, monkeypatch):
        import time

        sleeps: list[float] = []
        monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
        respx.post(f"{_BASE}/scan/").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "2"}, text="rate limited"),
                httpx.Response(429, headers={"Retry-After": "2"}, text="rate limited"),
                httpx.Response(429, text="rate limited"),
            ]
        )
        client = _make_client()
        with pytest.raises(IronclawRetryExhausted):
            client.scan(_make_request())
        assert len(sleeps) == 2
        assert sleeps[0] == 2.0
        assert sleeps[1] == 2.0

    @respx.mock
    def test_non_retryable_400_does_not_retry(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(400, json={"detail": "bad request"}))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.scan(_make_request())
        assert route.call_count == 1

    @respx.mock
    def test_pending_purchase_response_does_not_retry(self):
        route = respx.post(f"{_BASE}/billing/purchase").mock(return_value=httpx.Response(500, json={"detail": "Purchase is pending payment fulfillment."}))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.purchase_package(
                package_id="pkg_5000",
                buyer_name="Ada",
                buyer_email="ada@example.com",
            )
        assert route.call_count == 1

    @respx.mock
    def test_invalid_install_key_response_does_not_retry(self):
        route = respx.get(f"{_BASE}/install-keys/my-keys").mock(return_value=httpx.Response(403, json={"detail": "Install key 'ic_install_openclaw_abc' is inactive or not available for paid entitlement."}))
        client = _make_client()
        with pytest.raises(IronclawAuthError):
            client.get_my_install_keys(owner_key="ada@example.com")
        assert route.call_count == 1


@pytest.mark.sdk
class TestTimeoutHandling:
    @respx.mock
    def test_timeout_raises_ironclaw_timeout_error(self):
        respx.post(f"{_BASE}/scan/").mock(side_effect=httpx.TimeoutException("timed out"))
        client = _make_client()
        with pytest.raises(IronclawTimeoutError):
            client.scan(_make_request())


@pytest.mark.sdk
class TestScanResponseBinding:
    @respx.mock
    def test_scan_maps_response_body_to_scan_response_exactly(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client()
        result = client.scan(_make_request())
        assert isinstance(result, ScanResponse)
        assert result.scan_id == _VALID_SCAN_RESPONSE["scan_id"]
        assert result.verdict == _VALID_SCAN_RESPONSE["verdict"]
        assert result.risk_score == _VALID_SCAN_RESPONSE["risk_score"]
        assert result.summary == _VALID_SCAN_RESPONSE["summary"]
        assert result.target_type == _VALID_SCAN_RESPONSE["target_type"]
        assert result.target_value == _VALID_SCAN_RESPONSE["target_value"]
        assert result.review_status == _VALID_SCAN_RESPONSE["review_status"]
        assert result.sandbox_lane == _VALID_SCAN_RESPONSE["sandbox_lane"]
        assert result.untrusted == _VALID_SCAN_RESPONSE["untrusted"]

    @respx.mock
    def test_malformed_response_raises_api_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json={"broken": True}))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.scan(_make_request())

    @respx.mock
    def test_non_json_response_raises_api_error(self):
        respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, text="not json"))
        client = _make_client()
        with pytest.raises(IronclawAPIError):
            client.scan(_make_request())


@pytest.mark.sdk
class TestCustomBillingAndInstallKeyErrors:
    def test_billing_and_install_key_error_classes_are_distinct_and_exported(self):
        assert issubclass(IronclawPaymentPendingError, IronclawAPIError)
        assert issubclass(IronclawPaymentFailedError, IronclawAPIError)
        assert issubclass(IronclawInstallKeyInvalidError, IronclawAPIError)
        assert issubclass(IronclawInstallKeyOwnershipError, IronclawAuthError)
        assert issubclass(IronclawUnsupportedInstallPlatformError, IronclawAPIError)

        assert "Purchase is pending payment fulfillment." in str(IronclawPaymentPendingError())
        assert "failed or was cancelled" in str(IronclawPaymentFailedError())
        assert "invalid or inactive" in str(IronclawInstallKeyInvalidError())
        assert "does not match the authenticated owner" in str(IronclawInstallKeyOwnershipError())
        assert "Unsupported install platform" in str(IronclawUnsupportedInstallPlatformError("unknown"))

    def test_root_package_exports_full_billing_and_install_key_contract(self):
        exported = ironclaw_sdk
        assert exported.BillingPackagePurchaseRequest is not None
        assert exported.BillingPackagePurchaseResponse is not None
        assert exported.BillingPackagePurchaseView is not None
        assert exported.OwnerKeyBinding is not None
        assert exported.InstallKeyProgram is not None
        assert exported.PaymentStatus is not None
        assert exported.EntitlementStatus is not None
        assert exported.InstallKeySlotView is not None
        assert exported.InstallKeyRecordView is not None
        assert exported.InstallKeysResponse is not None
        assert exported.WalletBalanceView is not None
        assert exported.IronclawClient is not None

    def test_sdk_version_tracks_contract_change(self):
        assert ironclaw_sdk.__version__ == "1.1.0"


@pytest.mark.sdk
class TestBaseUrlOverride:
    @respx.mock
    def test_base_url_override_respected(self):
        alt_base = "http://alt-server:9000"
        route = respx.post(f"{alt_base}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client(base_url=alt_base)
        client.scan(_make_request())
        assert route.called

    @respx.mock
    def test_trailing_slash_stripped_from_base_url(self):
        route = respx.post(f"{_BASE}/scan/").mock(return_value=httpx.Response(200, json=_VALID_SCAN_RESPONSE))
        client = _make_client(base_url=f"{_BASE}/")
        client.scan(_make_request())
        assert route.called


@pytest.mark.sdk
class TestBillingAndInstallKeyContracts:
    @respx.mock
    def test_purchase_package_returns_pending_purchase_before_payment_fulfillment(self):
        payload = {
            "status": "ok",
            "service": "IronClaw-Security",
            "timestamp": "2026-05-22T00:00:00Z",
            "purchase": {
                "purchase_id": "purch_123",
                "package_id": "pkg_5000",
                "package_name": "Starter",
                "buyer_name": "Ada",
                "buyer_email": "ada@example.com",
                "owner_key": "ada@example.com",
                "price_usd": 20.0,
                "granted_units": 0,
                "token_coverage": 5000,
                "tokens_per_unit": 1000,
                "created_at": "2026-05-22T00:00:00Z",
                "metadata": {
                    "payment_status": "pending",
                    "fulfillment_status": "pending",
                    "install_keys_provisioned": False,
                    "units_credited": False,
                },
            },
            "wallet": {
                "wallet_id": "wallet_123",
                "owner_key": "ada@example.com",
                "balance_units": 0,
                "total_purchased_units": 0,
                "total_consumed_units": 0,
                "total_refunded_units": 0,
                "updated_at": "2026-05-22T00:00:00Z",
                "metadata": {},
            },
        }
        respx.post(f"{_BASE}/billing/purchase").mock(return_value=httpx.Response(201, json=payload))
        client = _make_client()

        result = client.purchase_package(
            package_id="pkg_5000",
            buyer_name="Ada",
            buyer_email="ada@example.com",
        )

        assert isinstance(result, BillingPackagePurchaseResponse)
        assert isinstance(result.purchase, BillingPackagePurchaseView)
        assert result.purchase.purchase_id == "purch_123"
        assert result.purchase.metadata["payment_status"] == "pending"
        assert result.purchase.metadata["fulfillment_status"] == "pending"
        assert result.purchase.openclaw_install_key is None

    @respx.mock
    def test_get_purchase_status_tracks_fulfillment_after_successful_payment(self):
        payload = {
            "status": "ok",
            "service": "IronClaw-Security",
            "timestamp": "2026-05-22T00:00:00Z",
            "count": 1,
            "purchases": [
                {
                    "purchase_id": "purch_123",
                    "package_id": "pkg_5000",
                    "package_name": "Starter",
                    "buyer_name": "Ada",
                    "buyer_email": "ada@example.com",
                    "owner_key": "ada@example.com",
                    "price_usd": 20.0,
                    "granted_units": 5000,
                    "token_coverage": 5000,
                    "tokens_per_unit": 1000,
                    "created_at": "2026-05-22T00:00:00Z",
                    "payment_id": "pi_123",
                    "payment_status": "paid",
                    "entitlement_status": "active",
                    "metadata": {
                        "payment_status": "paid",
                        "fulfillment_status": "fulfilled",
                        "install_keys_provisioned": True,
                        "units_credited": True,
                    },
                }
            ],
        }
        respx.get(f"{_BASE}/billing/purchases").mock(return_value=httpx.Response(200, json=payload))
        client = _make_client()

        result = client.get_purchase_status(purchase_id="purch_123")

        assert isinstance(result, BillingPackagePurchaseView)
        assert result.purchase_id == "purch_123"
        assert result.metadata["payment_status"] == "paid"
        assert result.metadata["fulfillment_status"] == "fulfilled"

    @respx.mock
    def test_get_my_install_keys_returns_paid_slots_only(self):
        payload = {
            "status": "ok",
            "service": "IronClaw-Security",
            "timestamp": "2026-05-22T00:00:00Z",
            "owner_key": "ada@example.com",
            "has_active_entitlement": True,
            "keys": [
                {
                    "key_id": "ik_001",
                    "program": "openclaw",
                    "masked_key": "ic_install_openclaw_abcd",
                    "label": "OpenClaw",
                    "status": "active",
                    "active": True,
                    "payment_status": "paid",
                    "entitlements_status": "active",
                    "issued_after_payment": True,
                    "units_used": 12,
                    "units_remaining": 120,
                    "blocked_attacks": 4,
                    "created_at": "2026-05-22T00:00:00Z",
                    "last_used_at": "2026-05-22T00:00:00Z",
                    "metadata": {"purchase_id": "purch_123"},
                    "usage_summary": {"total_consumed_units": 12},
                }
            ],
        }
        respx.get(f"{_BASE}/install-keys/my-keys").mock(return_value=httpx.Response(200, json=payload))
        client = _make_client()

        result = client.get_my_install_keys(owner_key="ada@example.com")

        assert isinstance(result, InstallKeysResponse)
        assert result.owner_key == "ada@example.com"
        assert result.has_active_entitlement is True
        assert len(result.keys) == 1
        assert isinstance(result.keys[0], InstallKeySlotView)
        assert result.keys[0].payment_status == "paid"
        assert result.keys[0].program == "openclaw"

    @respx.mock
    def test_purchase_request_model_rejects_invalid_billing_payload(self):
        with pytest.raises(ValueError):
            BillingPackagePurchaseRequest(
                package_id="",
                buyer_name="Ada",
                buyer_email="ada@example.com",
            )
