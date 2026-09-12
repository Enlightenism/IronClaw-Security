from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.billing as billing_api
from app.core.auth import AuthContext, require_auth_context

app = FastAPI()
app.include_router(billing_api.router)
auth = AuthContext(
    api_key="test-api-key",
    principal_type="api_key",
    principal_id="user-123",
    session_id=None,
    org_id=None,
    authenticated=True,
    auth_source="test",
    auth_method="api_key",
    key_type="personal",
)
app.dependency_overrides[require_auth_context] = lambda: auth
client = TestClient(app, raise_server_exceptions=True)

resp = client.post("/billing/packages/purchase", json={"package_id": "pkg_5000", "buyer_name": "Paid Buyer", "buyer_email": "paid@example.com", "metadata": {}})
print("CREATE", resp.status_code)
print(resp.json())
purchase_id = resp.json()["purchase"]["purchase_id"]
resp2 = client.post(f"/billing/packages/{purchase_id}/fulfill", params={"payment_id": "pay_123", "payment_status": "paid", "entitlement_status": "active"})
print("FULFILL", resp2.status_code)
print(resp2.text)
resp3 = client.post("/billing/wallet/alice@example.com/debit", json={"units": 300, "reason": "usage"})
print("DEBIT", resp3.status_code)
print(resp3.text)
