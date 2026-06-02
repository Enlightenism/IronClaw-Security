from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import os
from pathlib import Path
import random
import secrets
import uuid

import bcrypt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
import jwt
from pydantic import BaseModel, EmailStr, Field
from starlette.middleware.cors import CORSMiddleware

from supabase_client import _request

try:
    from stripe_checkout import (
        CheckoutSessionRequest,
        CheckoutSessionResponse,
        CheckoutStatusResponse,
        StripeCheckout,
    )
except ImportError:
    from app.stripe_checkout import (  # type: ignore[no-redef]
        CheckoutSessionRequest,
        CheckoutSessionResponse,
        CheckoutStatusResponse,
        StripeCheckout,
    )


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")


# ---------------------------------------------------------------------------
# Auth / Stripe config
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_DAYS = 7
STRIPE_API_KEY = os.environ["STRIPE_API_KEY"]


# ---------------------------------------------------------------------------
# App / router / security
# ---------------------------------------------------------------------------
app = FastAPI(title="IronClaw-Security API")
api_router = APIRouter(prefix="/api")
security_scheme = HTTPBearer(auto_error=True)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ironclaw")


# ---------------------------------------------------------------------------
# Fixed server-side packages (NEVER trust amounts from the frontend)
# Retired IDs aliased so orphaned checkout sessions still resolve correctly.
# ---------------------------------------------------------------------------
PACKAGES = {
    "tier_10k": {"units": 10000, "amount": 20.00, "label": "10,000 units"},
    "tier_50k": {"units": 50000, "amount": 90.00, "label": "50,000 units"},
    "tier_100k": {"units": 100000, "amount": 150.00, "label": "100,000 units"},
}

ACTIVE_PACKAGE_IDS = {"tier_10k", "tier_50k", "tier_100k"}


THREAT_TYPES = [
    "Prompt Injection",
    "Unsafe Tool Execution",
    "Data Exfiltration",
    "Sandbox Escape",
    "Policy Violation",
    "Jailbreak Attempt",
    "Credential Leak",
    "SSRF Attempt",
    "Malicious Tool Call",
    "Trust Boundary Breach",
]
PLATFORMS = ["claude-code", "openclaw"]


# ---------------------------------------------------------------------------
# CORS origins — env-driven
# ---------------------------------------------------------------------------
_raw_origins = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173",
)
CORS_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]


# ---------------------------------------------------------------------------
# Frontend build path — CRA outputs to build/, not dist/
# ---------------------------------------------------------------------------
_FRONTEND_BUILD = ROOT_DIR.parent / "frontend" / "build"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def verdict_for_score(score: int) -> str:
    if score < 30:
        return "ALLOW"
    if score < 60:
        return "WARN"
    if score < 85:
        return "QUARANTINE"
    return "BLOCK"


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)


class SigninRequest(BaseModel):
    email: EmailStr
    password: str


class CreateCheckoutRequest(BaseModel):
    package_id: str
    origin_url: str


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "exp": datetime.now(UTC) + timedelta(days=JWT_EXPIRE_DAYS),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# Supabase query helpers
# ---------------------------------------------------------------------------
def _sb_get_user_by_email(email: str) -> dict | None:
    rows = _request(
        "GET",
        "users",
        params={"email": f"eq.{email}", "limit": "1"},
        prefer="return=representation",
    )
    return rows[0] if rows else None


def _sb_get_user_by_id(user_id: str) -> dict | None:
    rows = _request(
        "GET",
        "users",
        params={"id": f"eq.{user_id}", "limit": "1"},
        prefer="return=representation",
    )
    return rows[0] if rows else None


def _sb_insert_user(user: dict) -> None:
    _request("POST", "users", json_body=user, prefer="return=minimal")


def _sb_update_user(user_id: str, patch: dict) -> None:
    _request(
        "PATCH",
        "users",
        json_body=patch,
        params={"id": f"eq.{user_id}"},
        prefer="return=minimal",
    )


def _sb_insert_events(events: list[dict]) -> None:
    _request("POST", "security_events", json_body=events, prefer="return=minimal")


def _sb_insert_event(event: dict) -> None:
    _request("POST", "security_events", json_body=event, prefer="return=minimal")


def _sb_get_events_by_user(user_id: str, limit: int = 2000) -> list[dict]:
    rows = _request(
        "GET",
        "security_events",
        params={"user_id": f"eq.{user_id}", "limit": str(limit)},
        prefer="return=representation",
    )
    return rows or []


def _sb_get_txn_by_session(session_id: str) -> dict | None:
    rows = _request(
        "GET",
        "payment_transactions",
        params={"session_id": f"eq.{session_id}", "limit": "1"},
        prefer="return=representation",
    )
    return rows[0] if rows else None


def _sb_insert_txn(txn: dict) -> None:
    _request("POST", "payment_transactions", json_body=txn, prefer="return=minimal")


def _sb_update_txn(session_id: str, patch: dict) -> None:
    _request(
        "PATCH",
        "payment_transactions",
        json_body=patch,
        params={"session_id": f"eq.{session_id}"},
        prefer="return=minimal",
    )


# ---------------------------------------------------------------------------
# get_current_user dependency
# ---------------------------------------------------------------------------
async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> dict:
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as err:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.") from err
    except jwt.PyJWTError as err:
        raise HTTPException(status_code=401, detail="Invalid authentication token.") from err
    user = _sb_get_user_by_id(payload.get("sub", ""))
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "user_token": user["user_token"],
        "wallet_units": user.get("wallet_units", 0),
        "has_paid": user.get("has_paid", False),
        "last_payment": user.get("last_payment"),
        "created_at": user.get("created_at"),
    }


# ---------------------------------------------------------------------------
# Seed simulated security events
# ---------------------------------------------------------------------------
def seed_security_events(user_id: str, count: int = 48) -> None:
    events = []
    now = datetime.now(UTC)
    for _ in range(count):
        offset_seconds = random.randint(0, 7 * 24 * 3600)
        ts = now - timedelta(seconds=offset_seconds)
        score = random.choices(
            [
                random.randint(2, 29),
                random.randint(30, 59),
                random.randint(60, 84),
                random.randint(85, 100),
            ],
            weights=[40, 28, 20, 12],
        )[0]
        events.append(
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "threat_type": random.choice(THREAT_TYPES),
                "risk_score": score,
                "verdict": verdict_for_score(score),
                "units_used": random.randint(3, 45),
                "platform": random.choice(PLATFORMS),
                "timestamp": ts.isoformat(),
            }
        )
    if events:
        _sb_insert_events(events)


def create_live_event(user_id: str) -> dict:
    score = random.choices(
        [
            random.randint(2, 29),
            random.randint(30, 59),
            random.randint(60, 84),
            random.randint(85, 100),
        ],
        weights=[35, 28, 22, 15],
    )[0]
    event = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "threat_type": random.choice(THREAT_TYPES),
        "risk_score": score,
        "verdict": verdict_for_score(score),
        "units_used": random.randint(3, 45),
        "platform": random.choice(PLATFORMS),
        "timestamp": now_iso(),
    }
    _sb_insert_event(event)
    user = _sb_get_user_by_id(user_id)
    if user:
        new_balance = max(0, user.get("wallet_units", 0) - event["units_used"])
        _sb_update_user(user_id, {"wallet_units": new_balance})
    return event


# ---------------------------------------------------------------------------
# Payment crediting (idempotent)
# ---------------------------------------------------------------------------
def credit_units_once(session_id: str) -> None:
    txn = _sb_get_txn_by_session(session_id)
    if not txn or txn.get("credited") is True:
        return
    _sb_update_txn(session_id, {"credited": True, "credited_at": now_iso()})
    user = _sb_get_user_by_id(txn["user_id"])
    if not user:
        return
    new_units = user.get("wallet_units", 0) + txn["units"]
    _sb_update_user(
        txn["user_id"],
        {
            "wallet_units": new_units,
            "has_paid": True,
            "last_payment": {
                "amount": txn["amount"],
                "units": txn["units"],
                "package_id": txn["package_id"],
                "label": PACKAGES.get(txn["package_id"], {}).get("label", ""),
                "date": now_iso(),
            },
        },
    )
    logger.info(
        "Credited %d units to user %s for session %s",
        txn["units"],
        txn["user_id"],
        session_id,
    )


def stripe_client(request: Request) -> StripeCheckout:
    host_url = str(request.base_url)
    webhook_url = f"{host_url}api/webhook/stripe"
    return StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@api_router.get("/")
async def root():
    return {"service": "IronClaw-Security", "status": "online"}


@api_router.post("/auth/signup")
async def signup(body: SignupRequest):
    email = body.email.lower().strip()
    existing = _sb_get_user_by_email(email)
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = {
        "id": str(uuid.uuid4()),
        "email": email,
        "password_hash": hash_password(body.password),
        "user_token": f"ic_live_{secrets.token_hex(20)}",
        "wallet_units": 0,
        "has_paid": False,
        "last_payment": None,
        "created_at": now_iso(),
    }
    _sb_insert_user(user)
    seed_security_events(user["id"])
    token = create_access_token(user)
    return {"token": token, "user": public_user(user)}


@api_router.post("/auth/signin")
async def signin(body: SigninRequest):
    email = body.email.lower().strip()
    user = _sb_get_user_by_email(email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    token = create_access_token(user)
    return {"token": token, "user": public_user(user)}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": public_user(user)}


@api_router.get("/integrations/token")
async def integrations_token(user: dict = Depends(get_current_user)):
    token = user["user_token"]
    return {
        "user_token": token,
        "claude_code_command": f"npx ironclaw-install --key {token} --platform claude-code",
        "openclaw_command": f"npx ironclaw-install --key {token} --platform openclaw",
    }


@api_router.get("/dashboard")
async def dashboard(user: dict = Depends(get_current_user)):
    events = _sb_get_events_by_user(user["id"], limit=2000)

    now = datetime.now(UTC)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    units_today = 0
    units_week = 0
    blocked_total = 0

    buckets = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        buckets.append({"key": day, "label": day.strftime("%a"), "date": day.strftime("%m/%d"), "units": 0})

    for e in events:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
        except Exception:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if e.get("verdict") in ("BLOCK", "QUARANTINE"):
            blocked_total += 1
        if ts >= today_start:
            units_today += e.get("units_used", 0)
        if ts >= week_start:
            units_week += e.get("units_used", 0)
        day_key = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        for b in buckets:
            if b["key"] == day_key:
                b["units"] += e.get("units_used", 0)
                break

    daily_usage = [{"label": b["label"], "date": b["date"], "units": b["units"]} for b in buckets]

    sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)
    attacks = [
        {
            "id": e["id"],
            "timestamp": e["timestamp"],
            "threat_type": e["threat_type"],
            "risk_score": e["risk_score"],
            "verdict": e["verdict"],
            "platform": e.get("platform", ""),
        }
        for e in sorted_events[:30]
    ]

    return {
        "wallet_units": user.get("wallet_units", 0),
        "units_today": units_today,
        "units_week": units_week,
        "total_threats_blocked": blocked_total,
        "total_events": len(events),
        "daily_usage": daily_usage,
        "attacks": attacks,
        "has_paid": user.get("has_paid", False),
        "last_payment": user.get("last_payment"),
    }


@api_router.post("/events/simulate")
async def simulate_events(user: dict = Depends(get_current_user)):
    n = random.randint(1, 3)
    created = [create_live_event(user["id"]) for _ in range(n)]
    return {"created": len(created), "events": created}


@api_router.post("/payments/create-checkout")
async def create_checkout(
    body: CreateCheckoutRequest,
    request: Request,
    user: dict = Depends(get_current_user),
):
    if body.package_id not in ACTIVE_PACKAGE_IDS:
        raise HTTPException(status_code=400, detail="Invalid package selected.")

    pkg = PACKAGES[body.package_id]

    origin = body.origin_url.rstrip("/")
    success_url = f"{origin}/dashboard?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{origin}/dashboard"

    metadata = {
        "user_id": user["id"],
        "email": user["email"],
        "package_id": body.package_id,
        "units": str(pkg["units"]),
        "source": "ironclaw_wallet",
    }

    checkout = stripe_client(request)
    req = CheckoutSessionRequest(
        amount=float(pkg["amount"]),
        currency="usd",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata=metadata,
    )
    session: CheckoutSessionResponse = await checkout.create_checkout_session(req)

    txn = {
        "id": str(uuid.uuid4()),
        "session_id": session.session_id,
        "user_id": user["id"],
        "email": user["email"],
        "package_id": body.package_id,
        "units": pkg["units"],
        "amount": float(pkg["amount"]),
        "currency": "usd",
        "metadata": metadata,
        "payment_status": "pending",
        "status": "initiated",
        "credited": False,
        "created_at": now_iso(),
    }
    _sb_insert_txn(txn)

    return {"url": session.url, "session_id": session.session_id}


@api_router.get("/payments/status/{session_id}")
async def payment_status(
    session_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
):
    txn = _sb_get_txn_by_session(session_id)
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found.")
    if txn["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized for this transaction.")

    checkout = stripe_client(request)
    cs: CheckoutStatusResponse = await checkout.get_checkout_status(session_id)

    _sb_update_txn(
        session_id,
        {
            "payment_status": cs.payment_status,
            "status": cs.status,
            "updated_at": now_iso(),
        },
    )

    if cs.payment_status == "paid":
        credit_units_once(session_id)

    return {
        "payment_status": cs.payment_status,
        "status": cs.status,
        "amount_total": cs.amount_total,
        "currency": cs.currency,
        "units": txn["units"],
        "package_id": txn["package_id"],
    }


@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    body = await request.body()
    sig = request.headers.get("Stripe-Signature")
    checkout = stripe_client(request)
    try:
        resp = await checkout.handle_webhook(body, sig)
    except Exception as exc:
        logger.error("Webhook handling failed: %s", exc)
        raise HTTPException(status_code=400, detail="Webhook verification failed.") from exc

    if resp.payment_status == "paid" and resp.session_id:
        _sb_update_txn(
            resp.session_id,
            {
                "payment_status": resp.payment_status,
                "status": "complete",
                "updated_at": now_iso(),
            },
        )
        credit_units_once(resp.session_id)

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Register API router BEFORE static mount so /api/* always wins
# ---------------------------------------------------------------------------
app.include_router(api_router)


# ---------------------------------------------------------------------------
# CORS — registered after routers, before static mount
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Static frontend — CRA builds to frontend/build/
# Served only when the build folder exists (safe for dev without a build)
# ---------------------------------------------------------------------------
if _FRONTEND_BUILD.is_dir():
    _assets_dir = _FRONTEND_BUILD / "static"
    if _assets_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(_assets_dir)), name="static")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        """Catch-all: serve index.html for all non-API routes (SPA client-side routing)."""
        index = _FRONTEND_BUILD / "index.html"
        if index.is_file():
            return FileResponse(str(index))
        raise HTTPException(status_code=404, detail="Frontend not built.")

else:
    logger.warning(
        "Frontend build not found at %s — static serving disabled. " "Run `yarn build` inside the frontend directory to enable it.",
        _FRONTEND_BUILD,
    )
