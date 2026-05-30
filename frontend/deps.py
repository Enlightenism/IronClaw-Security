from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import json
import logging
from typing import Any

from fastapi import Depends, Request, status
from fastapi.responses import RedirectResponse

from app.core.errors import AppError
from app.core.settings import get_settings

_log = logging.getLogger(__name__)

# ── Session cookie constants ──────────────────────────────────────────────────
_SESSION_COOKIE = "ironclaw_session"
_FLASH_COOKIE = "ironclaw_flash"
_ADMIN_ROLES: frozenset[str] = frozenset({"admin", "superadmin", "platform_admin"})

# ── CurrentUser dataclass ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CurrentUser:
    user_id: str
    username: str
    email: str
    role: str
    org_id: str
    authenticated: bool = True
    permissions: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return self.role.lower() in _ADMIN_ROLES

    @property
    def display_name(self) -> str:
        return self.username or self.email or self.user_id


# ── FlashMessage dataclass ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FlashMessage:
    level: str  # "success" | "warning" | "error" | "info"
    message: str

    @property
    def is_error(self) -> bool:
        return self.level == "error"

    @property
    def is_success(self) -> bool:
        return self.level == "success"


# ── Redirect sentinel ─────────────────────────────────────────────────────────


class _LoginRedirect(Exception):
    """Internal signal to redirect unauthenticated requests to /login."""

    def __init__(self, next_path: str = "/dashboard") -> None:
        self.next_path = next_path


# ── Cookie helpers ────────────────────────────────────────────────────────────


def _read_session_cookie(request: Request) -> dict[str, Any] | None:
    raw = request.cookies.get(_SESSION_COOKIE)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        _log.debug("frontend.deps: session cookie parse failed")
        return None


def _read_flash_cookie(request: Request) -> FlashMessage | None:
    raw = request.cookies.get(_FLASH_COOKIE)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        level = str(data.get("level", "info")).strip().lower()
        message = str(data.get("message", "")).strip()
        if not message:
            return None
        return FlashMessage(level=level, message=message)
    except Exception:
        _log.debug("frontend.deps: flash cookie parse failed")
        return None


def _verify_session_signature(session_data: dict[str, Any]) -> bool:
    """
    Constant-time comparison of the session signature against the configured
    admin API key.  Falls back gracefully when auth is not required.
    """
    sig = session_data.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        return False

    try:
        settings = get_settings()
    except Exception:
        return False

    expected = settings.admin_api_key or settings.internal_platform_api_key or settings.platform_api_key or settings.api_key or settings.ironclaw_api_key

    if expected is None:
        # Auth not configured — accept any valid-looking session in dev mode
        return not settings.is_production

    return hmac.compare_digest(sig.strip(), expected.strip())


def _build_current_user(session_data: dict[str, Any]) -> CurrentUser:
    permissions_raw = session_data.get("permissions", [])
    permissions = tuple(str(p).strip() for p in permissions_raw if str(p).strip())

    metadata_raw = session_data.get("metadata", {})
    metadata = dict(metadata_raw) if isinstance(metadata_raw, dict) else {}

    return CurrentUser(
        user_id=str(session_data.get("user_id", "")).strip() or "anonymous",
        username=str(session_data.get("username", "")).strip(),
        email=str(session_data.get("email", "")).strip(),
        role=str(session_data.get("role", "viewer")).strip().lower(),
        org_id=str(session_data.get("org_id", "default")).strip(),
        authenticated=True,
        permissions=permissions,
        metadata=metadata,
    )


# ── Public helpers — used by auth pages (login/logout) ───────────────────────


def build_session_cookie_value(
    *,
    user_id: str,
    username: str,
    email: str,
    role: str,
    org_id: str,
    permissions: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """
    Serialize a session payload to JSON for writing into the session cookie.
    The caller is responsible for the cookie Set-Cookie header.
    """
    try:
        settings = get_settings()
        sig = settings.admin_api_key or settings.internal_platform_api_key or settings.platform_api_key or settings.api_key or settings.ironclaw_api_key or ""
    except Exception:
        sig = ""

    payload: dict[str, Any] = {
        "user_id": user_id.strip(),
        "username": username.strip(),
        "email": email.strip(),
        "role": role.strip().lower(),
        "org_id": org_id.strip(),
        "permissions": permissions or [],
        "metadata": metadata or {},
        "sig": sig,
    }
    return json.dumps(payload, separators=(",", ":"))


def clear_flash_cookie(response: Any) -> None:
    """Expire the flash cookie on a response object."""
    response.delete_cookie(_FLASH_COOKIE)


def set_flash_cookie(response: Any, *, level: str, message: str) -> None:
    """Write a one-shot flash message into the flash cookie."""
    payload = json.dumps({"level": level, "message": message}, separators=(",", ":"))
    response.set_cookie(
        _FLASH_COOKIE,
        payload,
        httponly=True,
        samesite="lax",
        max_age=60,
    )


# ── FastAPI Depends injectors ─────────────────────────────────────────────────


async def get_current_user(request: Request) -> CurrentUser:
    """
    Reads and validates the session cookie.
    Raises AppError(401) when the session is missing or invalid.
    Page handlers that want a redirect instead of a JSON error should
    catch AppError and return RedirectResponse("/login").
    """
    session_data = _read_session_cookie(request)

    if session_data is None:
        raise AppError(
            error="session_missing",
            message="No active session — please log in",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    if not _verify_session_signature(session_data):
        _log.warning(
            "frontend.deps: session signature mismatch — path=%s",
            request.url.path,
        )
        raise AppError(
            error="session_invalid",
            message="Session is invalid or expired — please log in again",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        return _build_current_user(session_data)
    except Exception as exc:
        _log.error("frontend.deps: failed to build CurrentUser — %s", exc)
        raise AppError(
            error="session_corrupt",
            message="Session data could not be read — please log in again",
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from exc


async def get_flash(request: Request) -> FlashMessage | None:
    """
    Reads the one-shot flash cookie and returns the FlashMessage.
    The cookie is cleared by calling clear_flash_cookie(response) in the
    page handler after rendering — this keeps the clear synchronised with
    the response object rather than requiring a background task.
    """
    return _read_flash_cookie(request)


async def require_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Raises AppError(403) if the authenticated user does not hold an admin role.
    Use as a route-level dependency on any admin-only page handler.
    """
    if not current_user.is_admin:
        _log.warning(
            "frontend.deps: admin access denied — user=%s role=%s",
            current_user.user_id,
            current_user.role,
        )
        raise AppError(
            error="forbidden",
            message="Admin access required",
            status_code=status.HTTP_403_FORBIDDEN,
            details={"required_roles": sorted(_ADMIN_ROLES), "current_role": current_user.role},
        )
    return current_user


def redirect_to_login(next_path: str = "/dashboard") -> RedirectResponse:
    """
    Convenience factory used by page handlers that catch AppError(401)
    and want to redirect to /login rather than return a JSON error.
    """
    url = f"/login?next={next_path}"
    return RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
