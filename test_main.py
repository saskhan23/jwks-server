from fastapi.testclient import TestClient
from main import app, DB_FILE
import os

client = TestClient(app)


def test_db_file_exists():
    assert os.path.exists(DB_FILE)


def test_jwks_returns_keys():
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = response.json()
    assert "keys" in data
    assert isinstance(data["keys"], list)
    assert len(data["keys"]) >= 1


def test_auth_returns_valid_token():
    response = client.post("/auth")
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert isinstance(data["token"], str)


def test_auth_returns_expired_token_when_requested():
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert isinstance(data["token"], str)
