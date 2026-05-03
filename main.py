from fastapi import FastAPI, Query, HTTPException, Request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import os, base64
import jwt
import time
import base64
import sqlite3

app = FastAPI()

DB_FILE = "totally_not_my_privateKeys.db"

def get_fernet():
    key = os.environ.get("NOT_MY_KEY", "fallbackkey1234567890123456789012")
    key = base64.urlsafe_b64encode(key.encode().ljust(32)[:32])
    return Fernet(key)

def get_db_connection():
    return sqlite3.connect(DB_FILE)


def generate_key_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def load_private_key_from_pem(pem_data):
    return serialization.load_pem_private_key(pem_data, password=None)


def rsa_to_jwk(private_key, kid):
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")

    e = base64.urlsafe_b64encode(e_bytes).rstrip(b"=").decode("utf-8")
    n = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("utf-8")

    return {
        "kty": "RSA",
        "use": "sig",
        "kid": str(kid),
        "alg": "RS256",
        "n": n,
        "e": e,
    }


def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP      
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]

        if count == 0:
            now = int(time.time())

            f = get_fernet()
            expired_key_pem = f.encrypt(generate_key_pem())
            valid_key_pem = f.encrypt(generate_key_pem())

            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (expired_key_pem, now - 3600),
            )

            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (valid_key_pem, now + 3600),
            )

        conn.commit()


@app.post("/register")
def register(user: dict):
    import uuid
    from argon2 import PasswordHasher

    username = user.get("username")
    email = user.get("email")

    if not username or not email:
        raise HTTPException(status_code=400, detail="Missing username or email")

    password = str(uuid.uuid4())

    ph = PasswordHasher()
    password_hash = ph.hash(password)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                (username, password_hash, email)
            )
            conn.commit()
        except:
            raise HTTPException(status_code=400, detail="User already exists")

    return {"password": password}


@app.get("/.well-known/jwks.json")
def jwks():
    now = int(time.time())

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
        rows = cursor.fetchall()

    keys = []
    for kid, pem_data, _exp in rows:
        f = get_fernet() 
        decrypted = f.decrypt(pem_data)
        private_key = load_private_key_from_pem(decrypted)
        keys.append(rsa_to_jwk(private_key, kid))

    return {"keys": keys}


@app.post("/auth")
def auth(request: Request, expired: bool = Query(False)):
    now = int(time.time())

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if expired:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
                (now,),
            )
        else:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
                (now,),
            )

        row = cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="No suitable key found")

    kid, pem_data, expiry = row
    f = get_fernet()
    decrypted = f.decrypt(pem_data)
    private_key = load_private_key_from_pem(decrypted)

    payload = {
        "sub": "userABC",
        "iat": now,
        "exp": expiry,
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)},
    )

    #LOG AUTH REQUEST
    ip = request.client.host

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
            (ip, None)
        )
        conn.commit()

    return {"token": token}


init_db()