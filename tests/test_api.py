from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200

def test_scan_and_history_lookup():
    scan_response = client.post("/scan/", json={
        "target_type": "url",
        "target_value": "https://example.com"
    })
    assert scan_response.status_code == 200
    scan_data = scan_response.json()
    assert "scan_id" in scan_data

    history_response = client.get("/history/")
    assert history_response.status_code == 200
    history_data = history_response.json()
    assert "items" in history_data
    assert isinstance(history_data["items"], list)

    lookup_response = client.get(f"/history/{scan_data['scan_id']}")
    assert lookup_response.status_code == 200
    lookup_data = lookup_response.json()
    assert lookup_data["scan_id"] == scan_data["scan_id"]
