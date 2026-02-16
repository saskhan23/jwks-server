from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_jwks_endpoint():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json()

def test_auth_valid():
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json()

def test_auth_expired():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    assert "token" in response.json()
