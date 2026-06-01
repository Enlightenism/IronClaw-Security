from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import uuid
import secrets
import random
import jwt
import bcrypt
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timezone, timedelta

from emergentintegrations.payments.stripe.checkout import (
    StripeCheckout,
    CheckoutSessionResponse,
    CheckoutStatusResponse,
    CheckoutSessionRequest,
)

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Auth config
JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_EXPIRE_DAYS = 7
STRIPE_API_KEY = os.environ['STRIPE_API_KEY']

app = FastAPI(title="IronClaw-Security API")
api_router = APIRouter(prefix="/api")
security_scheme = HTTPBearer(auto_error=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ironclaw")

# ---------------------------------------------------------------------------
# Fixed server-side packages (NEVER trust amounts from the frontend)
# ---------------------------------------------------------------------------
PACKAGES = {
    "tier_20k": {"units": 20000, "amount": 20.00, "label": "20,000 units"},
    "tier_100k": {"units": 100000, "amount": 90.00, "label": "100,000 units"},
    "tier_200k": {"units": 200000, "amount": 150.00, "label": "200,000 units"},
}

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


def verdict_for_score(score: int) -> str:
    if score < 30:
        return "ALLOW"
    if score < 60:
        return "WARN"
    if score < 85:
        return "QUARANTINE"
    return "BLOCK"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication token.")
    user = await db.users.find_one({"id": payload.get("sub")}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "user_token": user["user_token"],
        "wallet_units": user.get("wallet_units", 0),
        "created_at": user.get("created_at"),
    }


# ---------------------------------------------------------------------------
# Seed simulated security events
# ---------------------------------------------------------------------------
async def seed_security_events(user_id: str, count: int = 48):
    events = []
    now = datetime.now(timezone.utc)
    for _ in range(count):
        offset_seconds = random.randint(0, 7 * 24 * 3600)
        ts = now - timedelta(seconds=offset_seconds)
        score = random.choices(
            [random.randint(2, 29), random.randint(30, 59), random.randint(60, 84), random.randint(85, 100)],
            weights=[40, 28, 20, 12],
        )[0]
        events.append({
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "threat_type": random.choice(THREAT_TYPES),
            "risk_score": score,
            "verdict": verdict_for_score(score),
            "units_used": random.randint(3, 45),
            "platform": random.choice(PLATFORMS),
            "timestamp": ts.isoformat(),
        })
    if events:
        await db.security_events.insert_many(events)


async def create_live_event(user_id: str) -> dict:
    score = random.choices(
        [random.randint(2, 29), random.randint(30, 59), random.randint(60, 84), random.randint(85, 100)],
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
    await db.security_events.insert_one(event)
    event.pop("_id", None)
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user:
        new_balance = max(0, user.get("wallet_units", 0) - event["units_used"])
        await db.users.update_one({"id": user_id}, {"$set": {"wallet_units": new_balance}})
    return event


# ---------------------------------------------------------------------------
# Payment crediting (idempotent)
# ---------------------------------------------------------------------------
async def credit_units_once(session_id: str):
    txn = await db.payment_transactions.find_one_and_update(
        {"session_id": session_id, "credited": {"$ne": True}},
        {"$set": {"credited": True, "credited_at": now_iso()}},
    )
    if not txn:
        return
    await db.users.update_one(
        {"id": txn["user_id"]},
        {
            "$inc": {"wallet_units": txn["units"]},
            "$set": {
                "has_paid": True,
                "last_payment": {
                    "amount": txn["amount"],
                    "units": txn["units"],
                    "package_id": txn["package_id"],
                    "label": PACKAGES.get(txn["package_id"], {}).get("label", ""),
                    "date": now_iso(),
                },
            },
        },
    )
    logger.info(f"Credited {txn['units']} units to user {txn['user_id']} for session {session_id}")


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
    existing = await db.users.find_one({"email": email})
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
    await db.users.insert_one(user)
    await seed_security_events(user["id"])
    token = create_access_token(user)
    return {"token": token, "user": public_user(user)}


@api_router.post("/auth/signin")
async def signin(body: SigninRequest):
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email}, {"_id": 0})
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
    events = await db.security_events.find({"user_id": user["id"]}, {"_id": 0}).to_list(2000)

    now = datetime.now(timezone.utc)
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
            ts = ts.replace(tzinfo=timezone.utc)
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
    created = [await create_live_event(user["id"]) for _ in range(n)]
    return {"created": len(created), "events": created}


@api_router.post("/payments/create-checkout")
async def create_checkout(body: CreateCheckoutRequest, request: Request, user: dict = Depends(get_current_user)):
    pkg = PACKAGES.get(body.package_id)
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid package selected.")

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
    await db.payment_transactions.insert_one(txn)

    return {"url": session.url, "session_id": session.session_id}


@api_router.get("/payments/status/{session_id}")
async def payment_status(session_id: str, request: Request, user: dict = Depends(get_current_user)):
    txn = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found.")
    if txn["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not authorized for this transaction.")

    checkout = stripe_client(request)
    cs: CheckoutStatusResponse = await checkout.get_checkout_status(session_id)

    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": {"payment_status": cs.payment_status, "status": cs.status, "updated_at": now_iso()}},
    )

    if cs.payment_status == "paid":
        await credit_units_once(session_id)

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
        logger.error(f"Webhook handling failed: {exc}")
        raise HTTPException(status_code=400, detail="Webhook verification failed.")

    if resp.payment_status == "paid" and resp.session_id:
        await db.payment_transactions.update_one(
            {"session_id": resp.session_id},
            {"$set": {"payment_status": resp.payment_status, "status": "complete", "updated_at": now_iso()}},
        )
        await credit_units_once(resp.session_id)

    return {"status": "ok"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
