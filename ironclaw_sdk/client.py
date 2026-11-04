from __future__ import annotations

import os
from typing import Any, Final

import httpx

from ironclaw_sdk.exceptions import IronclawAPIError, IronclawAuthError, IronclawTimeoutError
from ironclaw_sdk.models import (
    BatchScanRequest,
    BatchScanResponse,
    BillingPackagePurchaseRequest,
    BillingPackagePurchaseResponse,
    BillingPackagePurchaseView,
    GuardBundleRequest,
    GuardBundleResponse,
    InstallKeysResponse,
    ScanRequest,
    ScanResponse,
)
from ironclaw_sdk.retry import execute_with_retry

_DEFAULT_BASE_URL: Final[str] = "http://localhost:8000"
_DEFAULT_CONNECT_TIMEOUT: Final[float] = 5.0
_DEFAULT_READ_TIMEOUT: Final[float] = 10.0
_API_KEY_HEADER: Final[str] = "X-API-Key"


class IronclawClient:
    """Hardened SDK client for the IronClaw Security API.

    Distinct from IronClawScanClient (ironclaw_client.py) — this is the
    versioned SDK entry point with full auth injection, structured model
    binding, retry, and strict error propagation. Never swallows exceptions.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = _DEFAULT_READ_TIMEOUT,
    ) -> None:
        raw_key = api_key if api_key is not None else os.environ.get("IRONCLAW_API_KEY", "")
        resolved_key = raw_key.strip()
        if not resolved_key:
            raise IronclawAuthError(
                status_code=401,
                message="IRONCLAW_API_KEY is required but was not provided.",
            )
        self._api_key = resolved_key
        self.base_url = (base_url or os.environ.get("IRONCLAW_BASE_URL", _DEFAULT_BASE_URL)).rstrip("/")
        self._timeout = httpx.Timeout(
            connect=connect_timeout,
            read=read_timeout,
            write=read_timeout,
            pool=connect_timeout,
        )

    def _headers(self) -> dict[str, str]:
        return {
            _API_KEY_HEADER: self._api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _handle_response(self, response: httpx.Response) -> httpx.Response:
        if response.status_code in (401, 403):
            raise IronclawAuthError(
                status_code=response.status_code,
                message=f"Authentication rejected by server (HTTP {response.status_code})",
            )
        if response.status_code >= 400:
            try:
                body = response.text
            except Exception:
                body = ""
            raise IronclawAPIError(status_code=response.status_code, body=body)
        return response

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(self, request: ScanRequest) -> ScanResponse:
        url = f"{self.base_url}/scan/"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers=self._headers()) as client:
                return client.post(url, content=request.model_dump_json())

        try:
            response = execute_with_retry(_call)
        except IronclawTimeoutError:
            raise
        except IronclawAuthError:
            raise

        self._handle_response(response)

        try:
            return ScanResponse.model_validate(response.json())
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"Response validation failed: {exc}",
            ) from exc

    def scan_text(self, text: str, client_id: str | None = None) -> ScanResponse:
        return self.scan(ScanRequest(target_type="text", target_value=text, client_id=client_id))

    def scan_prompt(self, prompt: str, client_id: str | None = None) -> ScanResponse:
        return self.scan(ScanRequest(target_type="prompt", target_value=prompt, client_id=client_id))

    # ------------------------------------------------------------------
    # Batch scan
    # ------------------------------------------------------------------

    def batch_scan(self, request: BatchScanRequest) -> BatchScanResponse:
        url = f"{self.base_url}/scan/batch"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers=self._headers()) as client:
                return client.post(url, content=request.model_dump_json())

        try:
            response = execute_with_retry(_call)
        except IronclawTimeoutError:
            raise
        except IronclawAuthError:
            raise

        self._handle_response(response)

        try:
            return BatchScanResponse.model_validate(response.json())
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"Batch response validation failed: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Billing / purchase lifecycle
    # ------------------------------------------------------------------

    def purchase_package(
        self,
        *,
        package_id: str,
        buyer_name: str,
        buyer_email: str,
        metadata: dict[str, Any] | None = None,
    ) -> BillingPackagePurchaseResponse:
        request = BillingPackagePurchaseRequest(
            package_id=package_id,
            buyer_name=buyer_name,
            buyer_email=buyer_email,
            metadata=metadata or {},
        )
        url = f"{self.base_url}/billing/purchase"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers=self._headers()) as client:
                return client.post(url, content=request.model_dump_json(exclude_none=True))

        try:
            response = execute_with_retry(_call)
        except IronclawTimeoutError:
            raise
        except IronclawAuthError:
            raise

        self._handle_response(response)

        try:
            payload = response.json()
            return BillingPackagePurchaseResponse.model_validate(payload)
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"Billing purchase response validation failed: {exc}",
            ) from exc

    def get_purchase_status(self, purchase_id: str) -> BillingPackagePurchaseView:
        url = f"{self.base_url}/billing/purchases"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers=self._headers()) as client:
                return client.get(url, params={"limit": 100})

        try:
            response = execute_with_retry(_call)
        except IronclawTimeoutError:
            raise
        except IronclawAuthError:
            raise

        self._handle_response(response)

        try:
            payload = response.json()
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"Billing purchase list response was not JSON: {exc}",
            ) from exc

        items = payload.get("purchases", []) if isinstance(payload, dict) else []
        for item in items:
            if str(item.get("purchase_id") or "") == purchase_id:
                try:
                    return BillingPackagePurchaseView.model_validate(item)
                except Exception as exc:
                    raise IronclawAPIError(
                        status_code=response.status_code,
                        body=f"Purchase response validation failed: {exc}",
                    ) from exc

        raise IronclawAPIError(
            status_code=404,
            body=f"Purchase {purchase_id!r} was not found in the billing list response.",
        )

    # ------------------------------------------------------------------
    # Install keys
    # ------------------------------------------------------------------

    def get_my_install_keys(self, install_key: str) -> InstallKeysResponse:
        """Return the status and usage of the install key the caller authenticates with.

        Ownership is derived server-side from the install key, so no owner key is sent.
        """
        url = f"{self.base_url}/install-key-events/self"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers={"X-Install-Key": install_key, "Accept": "application/json"}) as client:
                return client.get(url)

        try:
            response = execute_with_retry(_call)
        except IronclawTimeoutError:
            raise
        except IronclawAuthError:
            raise

        self._handle_response(response)

        try:
            return InstallKeysResponse.model_validate(response.json())
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"Install keys response validation failed: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Guard bundle  (POST /policy/guard-bundle)
    # ------------------------------------------------------------------

    def guard_bundle(self, request: GuardBundleRequest) -> GuardBundleResponse:
        """Submit a multi-slot prompt bundle for policy evaluation.

        Raises IronclawAPIError if the server returns a non-2xx that is not
        retryable; raises IronclawAuthError on 401/403; raises
        IronclawTimeoutError on connect/read timeout.

        Does NOT raise on a block verdict — callers must inspect
        ``response.should_halt`` themselves. This is intentional: the SDK
        enforces trust but never silently halts caller execution.
        """
        url = f"{self.base_url}/policy/guard-bundle"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers=self._headers()) as client:
                return client.post(url, content=request.model_dump_json(exclude_none=True))

        try:
            response = execute_with_retry(_call)
        except IronclawTimeoutError:
            raise
        except IronclawAuthError:
            raise

        self._handle_response(response)

        try:
            return GuardBundleResponse.model_validate(response.json())
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"GuardBundle response validation failed: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        url = f"{self.base_url}/health"

        def _call() -> httpx.Response:
            with httpx.Client(timeout=self._timeout, headers=self._headers()) as client:
                return client.get(url)

        response = execute_with_retry(_call)
        self._handle_response(response)

        try:
            return response.json()
        except Exception as exc:
            raise IronclawAPIError(
                status_code=response.status_code,
                body=f"Health response not JSON: {exc}",
            ) from exc


__all__ = ["IronclawClient"]
