from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import logging
import time
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from app.core.settings import get_settings

_log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_COOKIE_NAME: str = "ic_session"
_COOKIE_MAX_AGE: int = 60 * 60 * 8  # 8 hours
_COOKIE_PATH: str = "/"
_SESSION_VERSION: str = "v1"
_HMAC_ALGO: str = "sha256"
_SEPARATOR: str = "|"

_ADMIN_ROLES: frozenset[str] = frozenset({"admin", "superadmin", "platform_admin"})
_OPERATOR_ROLES: frozenset[str] = frozenset({"operator", "admin", "superadmin", "platform_admin"})

# ── CurrentUser dataclass ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CurrentUser:
    username: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    authenticated_at: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return bool(_ADMIN_ROLES.intersection(self.roles))

    @property
    def is_operator(self) -> bool:
        return bool(_OPERATOR_ROLES.intersection(self.roles))

    def has_role(self, role: str) -> bool:
        return role in self.roles

    @property
    def display_name(self) -> str:
        return self.username or "anonymous"


# ── Signing secret ────────────────────────────────────────────────────────────


def _signing_secret() -> bytes:
    """
    Derive a stable signing secret from the configured API key chain.
    Raises in production if auth is required but no key is configured.
    Uses PBKDF2 to derive a fixed-length secret from the raw API key.
    """
    s = get_settings()
    key = s.effective_platform_api_key
    if not key:
        if s.auth_required:
            raise RuntimeError("AUTH_REQUIRED is true but no API key is configured. Set one of: INTERNAL_PLATFORM_API_KEY, PLATFORM_API_KEY, ADMIN_API_KEY, API_KEY, or IRONCLAW_API_KEY.")
        key = "ironclaw-dev-insecure-cookie-secret"
    # PBKDF2 stretch: prevents direct key reuse as signing material
    return hashlib.pbkdf2_hmac(
        "sha256",
        key.encode("utf-8"),
        b"ironclaw-session-v1",
        iterations=100_000,
        dklen=32,
    )


# ── Token construction ────────────────────────────────────────────────────────


def _build_payload(user: CurrentUser) -> str:
    roles_csv = ",".join(sorted(user.roles)) if user.roles else ""
    issued_at = str(int(user.authenticated_at))
    return _SEPARATOR.join([_SESSION_VERSION, user.username, roles_csv, issued_at])


def _sign(payload: str) -> str:
    secret = _signing_secret()
    return hmac.new(secret, payload.encode("utf-8"), _HMAC_ALGO).hexdigest()


def _build_token(user: CurrentUser) -> str:
    payload = _build_payload(user)
    sig = _sign(payload)
    return f"{payload}{_SEPARATOR}{sig}"


def _verify_token(token: str) -> CurrentUser | None:
    """
    Constant-time HMAC verify + expiry check.
    Returns None on any failure — never raises.
    """
    try:
        parts = token.split(_SEPARATOR)
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

        roles: tuple[str, ...] = tuple(r for r in roles_csv.split(",") if r) if roles_csv else ()

        return CurrentUser(
            username=username.strip(),
            roles=roles,
            authenticated_at=issued_at,
        )
    except Exception as exc:
        _log.warning("auth_context: token verification failed — %s", exc)
        return None


# ── Cookie writers ────────────────────────────────────────────────────────────


def set_session_cookie(response: Response, user: CurrentUser) -> None:
    """Write HttpOnly, SameSite=Lax, Secure-in-prod session cookie."""
    s = get_settings()
    token = _build_token(user)
    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=s.is_production,
        max_age=_COOKIE_MAX_AGE,
        path=_COOKIE_PATH,
    )


def clear_session_cookie(response: Response) -> None:
    """Expire the session cookie."""
    response.delete_cookie(key=_COOKIE_NAME, path=_COOKIE_PATH)


# ── FastAPI dependency injectors ──────────────────────────────────────────────


def _is_json_client(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    return "application/json" in accept or "application/json" in content_type


def _extract_user_from_request(request: Request) -> CurrentUser | None:
    token = request.cookies.get(_COOKIE_NAME)
    if token:
        user = _verify_token(token)
        if user:
            return user

    # Fallback: legacy deps.py cookie format (ironclaw_session) for migration
    legacy_token = request.cookies.get("ironclaw_session")
    if legacy_token:
        try:
            import json as _json

            data = _json.loads(legacy_token)
            username = str(data.get("username") or data.get("user_id") or "").strip()
            role = str(data.get("role", "viewer")).strip().lower()
            if username:
                roles_list: tuple[str, ...] = (role,) if role else ()
                return CurrentUser(username=username, roles=roles_list)
        except Exception:
            pass

    return None


async def get_optional_user(request: Request) -> CurrentUser | None:
    """
    FastAPI dependency — returns CurrentUser or None.
    Never raises. Safe for public pages.
    """
    return _extract_user_from_request(request)


async def get_current_user(request: Request) -> CurrentUser:
    """
    FastAPI dependency — fail-closed.
    HTML clients  → 303 redirect to /login?next=<path>
    JSON clients  → 401 Unauthorized
    """
    user = _extract_user_from_request(request)
    if user is not None:
        return user

    if _is_json_client(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    next_path = str(request.url.path)
    return RedirectResponse(  # type: ignore[return-value]
        url=f"/login?next={next_path}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


async def require_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Raises 403 if the authenticated user is not an admin."""
    if not current_user.is_admin:
        _log.warning(
            "auth_context: admin access denied — user=%s roles=%s",
            current_user.username,
            current_user.roles,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "forbidden",
                "message": "Admin access required",
                "required_roles": sorted(_ADMIN_ROLES),
            },
        )
    return current_user


async def require_operator(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Raises 403 if the authenticated user is not an operator or admin."""
    if not current_user.is_operator:
        _log.warning(
            "auth_context: operator access denied — user=%s roles=%s",
            current_user.username,
            current_user.roles,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "forbidden",
                "message": "Operator access required",
                "required_roles": sorted(_OPERATOR_ROLES),
            },
        )
    return current_user


# ── API key login ─────────────────────────────────────────────────────────────


def validate_api_key_login(submitted_key: str) -> CurrentUser | None:
    """
    Constant-time comparison against all configured keys.
    Returns a CurrentUser with appropriate roles, or None if no key matches.
    Admin key → admin + operator roles.
    Any other configured key → operator role only.
    """
    if not submitted_key or not submitted_key.strip():
        return None

    s = get_settings()
    submitted = submitted_key.strip()

    # Build ordered candidate list: (key_value, roles_to_grant)
    candidates: list[tuple[str, tuple[str, ...]]] = []

    admin_key = s.admin_api_key
    if admin_key:
        candidates.append((admin_key, ("admin", "operator")))

    for key_attr in ("internal_platform_api_key", "platform_api_key", "api_key", "ironclaw_api_key"):
        val = getattr(s, key_attr, None)
        if val:
            candidates.append((val, ("operator",)))

    if not candidates:
        if not s.is_production:
            # Dev fallback: accept any non-empty key as operator
            return CurrentUser(
                username="dev-user",
                roles=("operator",),
            )
        return None

    matched_roles: tuple[str, ...] | None = None

    # Always run all comparisons — constant-time regardless of match position
    for candidate_key, grant_roles in candidates:
        if hmac.compare_digest(candidate_key.strip(), submitted):
            if matched_roles is None:
                matched_roles = grant_roles

    if matched_roles is None:
        return None

    username = "admin" if "admin" in matched_roles else "operator"
    return CurrentUser(username=username, roles=matched_roles)


# ── Typed aliases for page handler signatures ─────────────────────────────────

AuthUser = Annotated[CurrentUser, Depends(get_current_user)]
OptionalUser = Annotated[CurrentUser | None, Depends(get_optional_user)]
AdminUser = Annotated[CurrentUser, Depends(require_admin)]
OperatorUser = Annotated[CurrentUser, Depends(require_operator)]
