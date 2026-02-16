from fastapi import FastAPI, Query
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import time
import uuid
import base64

app = FastAPI()

def generate_key(expired=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = str(uuid.uuid4())
    expiry = int(time.time()) - 3600 if expired else int(time.time()) + 3600
    return {"key": key, "kid": kid, "expiry": expiry}

active_key = generate_key(False)
expired_key = generate_key(True)

def rsa_to_jwk(key, kid):
    public_key = key.public_key()
    numbers = public_key.public_numbers()

    e = base64.urlsafe_b64encode(numbers.e.to_bytes(3, "big")).rstrip(b"=")
    n = base64.urlsafe_b64encode(numbers.n.to_bytes(256, "big")).rstrip(b"=")

    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": n.decode(),
        "e": e.decode(),
    }

@app.get("/.well-known/jwks.json")
def jwks():
    now = int(time.time())
    keys = []
    if active_key["expiry"] > now:
        keys.append(rsa_to_jwk(active_key["key"], active_key["kid"]))
    return {"keys": keys}

@app.post("/auth")
def auth(expired: bool = Query(False)):
    key_obj = expired_key if expired else active_key
    payload = {
        "sub": "fake_user",
        "iat": int(time.time()),
        "exp": key_obj["expiry"],
    }
    token = jwt.encode(
        payload,
        key_obj["key"],
        algorithm="RS256",
        headers={"kid": key_obj["kid"]},
    )
    return {"token": token}
