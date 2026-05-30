from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import logging
import time
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Request, Response, status

from app.core.settings import get_settings

_log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_COOKIE_NAME: str = "ic_session"
_COOKIE_MAX_AGE: int = 60 * 60 * 8  # 8 hours
_COOKIE_PATH: str = "/"
_SESSION_VERSION: str = "v1"
_HMAC_ALGO: str = "sha256"
_SEPARATOR: str = "|"

# ── CurrentUser dataclass ────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CurrentUser:
    username: str
    roles: list[str] = field(default_factory=list)
    authenticated_at: float = field(default_factory=time.time)
    extra: dict = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles

    @property
    def is_operator(self) -> bool:
        return "operator" in self.roles or self.is_admin

    def has_role(self, role: str) -> bool:
        return role in self.roles


# ── Signing secret resolution ────────────────────────────────────────────────


def _signing_secret() -> bytes:
    """
    Derive a stable signing secret from the configured API key chain.
    Never falls through to a weak default in production — raises if auth
    is required but no key is present.
    """
    s = get_settings()
    key = s.effective_platform_api_key
    if not key:
        if s.auth_required:
            raise RuntimeError("AUTH_REQUIRED is true but no API key is configured. " "Set one of: INTERNAL_PLATFORM_API_KEY, PLATFORM_API_KEY, " "ADMIN_API_KEY, API_KEY, or IRONCLAW_API_KEY.")
        # Dev/test only — deterministic weak secret
        key = "ironclaw-dev-insecure-cookie-secret"
    return key.encode("utf-8")


# ── Cookie token construction ─────────────────────────────────────────────────


def _build_payload(user: CurrentUser) -> str:
    """
    Encode user identity into a pipe-delimited payload string.
    Format: version|username|roles_csv|issued_at
    """
    roles_csv = ",".join(sorted(user.roles)) if user.roles else ""
    issued_at = str(int(user.authenticated_at))
    return _SEPARATOR.join([_SESSION_VERSION, user.username, roles_csv, issued_at])


def _sign(payload: str) -> str:
    secret = _signing_secret()
    sig = hmac.new(secret, payload.encode("utf-8"), _HMAC_ALGO).hexdigest()
    return sig


def _build_token(user: CurrentUser) -> str:
    payload = _build_payload(user)
    sig = _sign(payload)
    return f"{payload}{_SEPARATOR}{sig}"


def _verify_token(token: str) -> CurrentUser | None:
    """
    Verify HMAC signature and decode the session payload.
    Returns None on any failure — caller is responsible for fail-closed logic.
    """
    try:
        parts = token.split(_SEPARATOR)
        # Expected: version, username, roles_csv, issued_at, signature = 5 parts
        if len(parts) != 5:
            return None

        version, username, roles_csv, issued_at_str, received_sig = parts

        if version != _SESSION_VERSION:
            _log.debug("auth_context: session version mismatch: %s", version)
            return None

        payload = _SEPARATOR.join([version, username, roles_csv, issued_at_str])
        expected_sig = _sign(payload)

        if not hmac.compare_digest(expected_sig, received_sig):
            _log.warning("auth_context: HMAC signature mismatch — possible token tampering")
            return None

        issued_at = float(issued_at_str)
        if time.time() - issued_at > _COOKIE_MAX_AGE:
            _log.debug("auth_context: session expired for user=%s", username)
            return None

        if not username or not username.strip():
            return None

        roles = [r for r in roles_csv.split(",") if r] if roles_csv else []

        return CurrentUser(
            username=username.strip(),
            roles=roles,
            authenticated_at=issued_at,
        )

    except Exception as exc:  # noqa: BLE001
        _log.debug("auth_context: token decode failed: %s", exc)
        return None


# ── Session cookie helpers ────────────────────────────────────────────────────


def set_session_cookie(response: Response, user: CurrentUser) -> None:
    """
    Write a signed, HttpOnly, SameSite=Lax session cookie onto the response.
    Secure flag is set when not in development mode.
    """
    token = _build_token(user)
    s = get_settings()
    secure = s.is_production or s.environment.value == "staging"

    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        max_age=_COOKIE_MAX_AGE,
        path=_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=secure,
    )
    _log.info(
        "auth_context: session cookie set for user=%s roles=%s secure=%s",
        user.username,
        user.roles,
        secure,
    )


def clear_session_cookie(response: Response) -> None:
    """Delete the session cookie (logout)."""
    response.delete_cookie(
        key=_COOKIE_NAME,
        path=_COOKIE_PATH,
        httponly=True,
        samesite="lax",
    )
    _log.info("auth_context: session cookie cleared")


# ── FastAPI dependency: optional user ────────────────────────────────────────


def get_optional_user(
    ic_session: Annotated[str | None, Cookie(alias=_COOKIE_NAME)] = None,
) -> CurrentUser | None:
    """
    Dependency that resolves the current user from the session cookie.
    Returns None if the cookie is absent or invalid — does NOT raise.
    Use this for routes that have optional auth (e.g., login page itself).
    """
    if not ic_session:
        return None
    return _verify_token(ic_session)


# ── FastAPI dependency: required user (fail-closed) ───────────────────────────


def get_current_user(
    request: Request,
    ic_session: Annotated[str | None, Cookie(alias=_COOKIE_NAME)] = None,
) -> CurrentUser:
    """
    Fail-closed dependency. Every protected route uses Depends(get_current_user).

    - Missing cookie    → 303 redirect to /login
    - Invalid/expired   → 303 redirect to /login
    - Auth disabled     → synthetic guest user (dev/test only)

    Browser requests (Accept: text/html) receive a redirect.
    API/XHR requests (Accept: application/json) receive 401.
    """
    s = get_settings()

    # Auth disabled in dev/test — return a synthetic admin user
    if not s.auth_required:
        return CurrentUser(
            username="dev-admin",
            roles=["admin", "operator"],
        )

    if not ic_session:
        _log.debug("auth_context: no session cookie — denying access to %s", request.url.path)
        return _fail_closed(request)

    user = _verify_token(ic_session)
    if user is None:
        _log.warning(
            "auth_context: invalid/expired session — denying access to %s",
            request.url.path,
        )
        return _fail_closed(request)

    return user


def _fail_closed(request: Request) -> CurrentUser:
    """
    Centralised fail-closed branch.
    HTML clients get a 303 redirect to /login.
    JSON/API clients get a 401 with a structured error body.
    Never returns a user — always raises.
    """
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        redirect_url = f"/login?next={request.url.path}"
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            detail="Session required",
            headers={"Location": redirect_url},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "unauthenticated",
            "message": "Valid session required. Please log in.",
        },
        headers={"WWW-Authenticate": "Cookie"},
    )


# ── Role-based access guards ──────────────────────────────────────────────────


def require_admin(
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    """Dependency that further restricts to admin role only."""
    if not user.is_admin:
        _log.warning(
            "auth_context: user=%s attempted admin action without admin role",
            user.username,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "forbidden",
                "message": "Admin role required.",
            },
        )
    return user


def require_operator(
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> CurrentUser:
    """Dependency that restricts to operator or admin role."""
    if not user.is_operator:
        _log.warning(
            "auth_context: user=%s attempted operator action without operator role",
            user.username,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "forbidden",
                "message": "Operator role required.",
            },
        )
    return user


# ── Login credential validation ───────────────────────────────────────────────


def validate_api_key_login(submitted_key: str) -> CurrentUser | None:
    """
    Validate a submitted API key against the configured key chain.
    Used by the login page handler — never used inside protected route deps.

    Key hierarchy (highest privilege first):
      internal_platform_api_key → admin
      admin_api_key             → admin
      platform_api_key          → operator
      api_key                   → operator
      ironclaw_api_key          → operator

    Returns CurrentUser on success, None on failure.
    Constant-time comparison on every key to prevent timing oracle.
    """
    if not submitted_key or not submitted_key.strip():
        return None

    s = get_settings()
    submitted = submitted_key.strip().encode("utf-8")

    def _ct_eq(stored: str | None) -> bool:
        if not stored:
            return False
        return hmac.compare_digest(stored.encode("utf-8"), submitted)

    if _ct_eq(s.internal_platform_api_key):
        return CurrentUser(username="internal-platform", roles=["admin", "operator"])
    if _ct_eq(s.admin_api_key):
        return CurrentUser(username="admin", roles=["admin", "operator"])
    if _ct_eq(s.platform_api_key):
        return CurrentUser(username="platform", roles=["operator"])
    if _ct_eq(s.api_key):
        return CurrentUser(username="api-user", roles=["operator"])
    if _ct_eq(s.ironclaw_api_key):
        return CurrentUser(username="ironclaw-user", roles=["operator"])

    return None


# ── Typed dependency aliases (import these in page handlers) ──────────────────

AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
OptionalUser = Annotated[CurrentUser | None, Depends(get_optional_user)]
AdminUser = Annotated[CurrentUser, Depends(require_admin)]
OperatorUser = Annotated[CurrentUser, Depends(require_operator)]
