from __future__ import annotations


class IronclawSDKError(Exception):
    """Base class for all IronClaw SDK exceptions."""


class IronclawAuthError(IronclawSDKError):
    """Raised when the API returns 401 or 403.

    Never swallowed — callers must handle explicitly.
    """

    def __init__(self, status_code: int, message: str = "") -> None:
        self.status_code = status_code
        self.message = message or f"Authentication failed (HTTP {status_code})"
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"IronclawAuthError(status_code={self.status_code}, message={self.message!r})"


class IronclawAPIError(IronclawSDKError):
    """Raised when the API returns an unexpected non-2xx status that is not
    401/403 and is not retryable, or when the response body cannot be decoded.

    Never swallowed — callers must handle explicitly.
    """

    def __init__(self, status_code: int, body: str = "") -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"IronClaw API error (HTTP {status_code}): {body}")

    def __repr__(self) -> str:
        return f"IronclawAPIError(status_code={self.status_code}, body={self.body!r})"


class IronclawPaymentPendingError(IronclawAPIError):
    """Raised when a purchase exists but payment has not been fulfilled yet."""

    def __init__(self, purchase_id: str | None = None, message: str = "") -> None:
        self.purchase_id = purchase_id
        self.message = message or "Purchase is pending payment fulfillment."
        super().__init__(status_code=402, body=self.message)


class IronclawPaymentFailedError(IronclawAPIError):
    """Raised when the payment lifecycle reaches a failed or cancelled terminal state."""

    def __init__(self, purchase_id: str | None = None, message: str = "") -> None:
        self.purchase_id = purchase_id
        self.message = message or "Purchase payment failed or was cancelled."
        super().__init__(status_code=402, body=self.message)


class IronclawInstallKeyInvalidError(IronclawAPIError):
    """Raised when an install key is missing, malformed, or invalid for activation."""

    def __init__(self, key_id: str | None = None, message: str = "") -> None:
        self.key_id = key_id
        self.message = message or "Install key is invalid or inactive."
        super().__init__(status_code=401, body=self.message)


class IronclawInstallKeyOwnershipError(IronclawAuthError):
    """Raised when an install key does not belong to the calling owner context."""

    def __init__(self, owner_key: str | None = None, message: str = "") -> None:
        self.owner_key = owner_key
        self.message = message or "Install key ownership does not match the authenticated owner."
        super().__init__(status_code=403, message=self.message)


class IronclawUnsupportedInstallPlatformError(IronclawAPIError):
    """Raised when the requested install-key platform is unsupported or unrecognized."""

    def __init__(self, platform: str | None = None, message: str = "") -> None:
        self.platform = platform
        self.message = message or f"Unsupported install platform: {platform!r}"
        super().__init__(status_code=422, body=self.message)


class IronclawRetryExhausted(IronclawSDKError):
    """Raised when all retry attempts are exhausted without a successful response.

    Never swallowed — callers must handle explicitly.
    """

    def __init__(self, attempts: int, last_status_code: int | None = None) -> None:
        self.attempts = attempts
        self.last_status_code = last_status_code
        msg = f"IronClaw SDK retry exhausted after {attempts} attempt(s)"
        if last_status_code is not None:
            msg += f" (last HTTP {last_status_code})"
        super().__init__(msg)

    def __repr__(self) -> str:
        return f"IronclawRetryExhausted(attempts={self.attempts}, last_status_code={self.last_status_code})"


class IronclawTimeoutError(IronclawSDKError):
    """Raised when a request exceeds the configured connect or read timeout.

    Never swallowed — callers must handle explicitly.
    """

    def __init__(self, message: str = "IronClaw SDK request timed out") -> None:
        self.message = message
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"IronclawTimeoutError(message={self.message!r})"


__all__ = [
    "IronclawSDKError",
    "IronclawAuthError",
    "IronclawAPIError",
    "IronclawPaymentPendingError",
    "IronclawPaymentFailedError",
    "IronclawInstallKeyInvalidError",
    "IronclawInstallKeyOwnershipError",
    "IronclawUnsupportedInstallPlatformError",
    "IronclawRetryExhausted",
    "IronclawTimeoutError",
]
