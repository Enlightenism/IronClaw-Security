"""IronClaw-Security backend API tests"""

import os
import uuid

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://enforcement-hub-7.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"


def _unique_email():
    return f"test_{uuid.uuid4().hex[:10]}@ironclaw.io"


@pytest.fixture(scope="module")
def signup_user():
    email = _unique_email()
    password = "defend123"
    r = requests.post(f"{API}/auth/signup", json={"email": email, "password": password}, timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    return {
        "email": email,
        "password": password,
        "token": data["token"],
        "user": data["user"],
    }


@pytest.fixture
def auth_headers(signup_user):
    return {"Authorization": f"Bearer {signup_user['token']}"}


# --- auth ---
class TestAuth:
    def test_signup_returns_token_and_user(self, signup_user):
        u = signup_user["user"]
        assert "id" in u and u["email"] == signup_user["email"]
        assert u["user_token"].startswith("ic_live_")
        assert u["wallet_units"] == 0
        assert isinstance(signup_user["token"], str) and len(signup_user["token"]) > 20

    def test_signup_duplicate_email_returns_409(self, signup_user):
        r = requests.post(
            f"{API}/auth/signup",
            json={"email": signup_user["email"], "password": "defend123"},
        )
        assert r.status_code == 409

    def test_signup_short_password_422(self):
        r = requests.post(f"{API}/auth/signup", json={"email": _unique_email(), "password": "abc"})
        assert r.status_code == 422

    def test_signin_valid(self, signup_user):
        r = requests.post(
            f"{API}/auth/signin",
            json={"email": signup_user["email"], "password": signup_user["password"]},
        )
        assert r.status_code == 200
        d = r.json()
        assert "token" in d and d["user"]["email"] == signup_user["email"]

    def test_signin_invalid(self, signup_user):
        r = requests.post(
            f"{API}/auth/signin",
            json={"email": signup_user["email"], "password": "WRONG_PASS"},
        )
        assert r.status_code == 401

    def test_me_without_token_401(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code in (401, 403)

    def test_me_invalid_token_401(self):
        r = requests.get(f"{API}/auth/me", headers={"Authorization": "Bearer not_a_real_token"})
        assert r.status_code == 401

    def test_me_valid(self, auth_headers, signup_user):
        r = requests.get(f"{API}/auth/me", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["user"]["email"] == signup_user["email"]


# --- dashboard / integrations ---
class TestDashboard:
    def test_dashboard_shape(self, auth_headers):
        r = requests.get(f"{API}/dashboard", headers=auth_headers)
        assert r.status_code == 200, r.text
        d = r.json()
        for key in (
            "wallet_units",
            "units_today",
            "units_week",
            "total_threats_blocked",
            "daily_usage",
            "attacks",
        ):
            assert key in d, f"missing {key}"
        assert isinstance(d["daily_usage"], list) and len(d["daily_usage"]) == 7
        assert isinstance(d["attacks"], list) and len(d["attacks"]) <= 30
        if d["attacks"]:
            a = d["attacks"][0]
            for k in ("timestamp", "threat_type", "risk_score", "verdict"):
                assert k in a, f"attack missing {k}"

    def test_dashboard_seeded_events_present(self, auth_headers):
        # signup seeds ~48 events
        r = requests.get(f"{API}/dashboard", headers=auth_headers)
        d = r.json()
        assert d.get("total_events", 0) >= 40

    def test_dashboard_unauthorized(self):
        r = requests.get(f"{API}/dashboard")
        assert r.status_code in (401, 403)

    def test_integrations_token(self, auth_headers, signup_user):
        r = requests.get(f"{API}/integrations/token", headers=auth_headers)
        assert r.status_code == 200
        d = r.json()
        supported_platforms = d.get("supported_platforms", [])
        assert supported_platforms
        assert "security-guardian" not in supported_platforms
        assert "security-guardian" not in d.get("install_metadata", {})

        for platform in supported_platforms:
            command_field = f"{platform.replace('-', '_')}_command"
            command = d.get(command_field, "")
            metadata = d.get("install_metadata", {}).get(platform, {})

            assert "install_key" not in metadata, f"install_key must not be exposed for {platform}"
            if d.get("status") == "locked":
                assert not command, f"command must be empty without a verified paid key for {platform}"
                assert metadata.get("available") is False
                continue

            assert command, f"missing command for {platform}"
            assert "--key" not in command, f"command for {platform} must not use --key"
            assert platform.lower() in command.lower(), f"platform marker missing for {platform}"
            assert command.startswith(("gh skill install ", "hermes skills install ")), f"non-generic command for {platform}"


# --- events simulate ---
class TestSimulate:
    def test_simulate_creates_events(self, auth_headers):
        r = requests.post(f"{API}/events/simulate", headers=auth_headers)
        assert r.status_code == 200
        d = r.json()
        assert 1 <= d["created"] <= 3
        assert len(d["events"]) == d["created"]
        for e in d["events"]:
            assert e["verdict"] in ("ALLOW", "WARN", "QUARANTINE", "BLOCK")

    def test_wallet_never_negative(self, auth_headers):
        for _ in range(3):
            requests.post(f"{API}/events/simulate", headers=auth_headers)
        r = requests.get(f"{API}/auth/me", headers=auth_headers)
        assert r.json()["user"]["wallet_units"] >= 0


# --- payments ---
class TestPayments:
    def test_invalid_package_400(self, auth_headers):
        r = requests.post(
            f"{API}/payments/create-checkout",
            headers=auth_headers,
            json={"package_id": "bogus_tier", "origin_url": "https://example.com"},
        )
        assert r.status_code == 400

    def test_create_checkout_tier_10k(self, auth_headers):
        # base tier: 10,000 units / $20
        r = requests.post(
            f"{API}/payments/create-checkout",
            headers=auth_headers,
            json={"package_id": "tier_10k", "origin_url": "https://example.com"},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert "url" in d and d["url"].startswith("http")
        assert "session_id" in d and len(d["session_id"]) > 5

    def test_create_checkout_tier_50k(self, auth_headers):
        # mid tier: 50,000 units / $90
        r = requests.post(
            f"{API}/payments/create-checkout",
            headers=auth_headers,
            json={"package_id": "tier_50k", "origin_url": "https://example.com"},
        )
        assert r.status_code == 200, r.text
        d = r.json()
        assert "url" in d and d["url"].startswith("http")
        assert "session_id" in d and len(d["session_id"]) > 5

    def test_payment_status_lookup(self, auth_headers):
        # top tier: 100,000 units / $150
        r = requests.post(
            f"{API}/payments/create-checkout",
            headers=auth_headers,
            json={"package_id": "tier_100k", "origin_url": "https://example.com"},
        )
        assert r.status_code == 200
        sid = r.json()["session_id"]
        r2 = requests.get(f"{API}/payments/status/{sid}", headers=auth_headers)
        assert r2.status_code == 200
        d = r2.json()
        assert "payment_status" in d and "status" in d
        assert d["units"] == 100000
        assert d["package_id"] == "tier_100k"

    def test_payment_status_unauthorized(self):
        r = requests.get(f"{API}/payments/status/sess_does_not_exist")
        assert r.status_code in (401, 403)
