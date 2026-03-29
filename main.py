from fastapi import FastAPI, Query, HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
import time
import base64
import sqlite3

app = FastAPI()

# Required SQLite database filename from the project instructions.
DB_FILE = "totally_not_my_privateKeys.db"


def get_db_connection():
    """
    Create and return a SQLite database connection.
    """
    return sqlite3.connect(DB_FILE)


def generate_key_pem():
    """
    Generate a new RSA private key and return it serialized in PEM format.

    PEM is used because SQLite cannot directly store cryptography key objects.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def load_private_key_from_pem(pem_data):
    """
    Deserialize a PEM-encoded RSA private key from the database
    back into a usable cryptography key object.
    """
    return serialization.load_pem_private_key(pem_data, password=None)


def rsa_to_jwk(private_key, kid):
    """
    Convert an RSA private key into a public JWK dictionary.

    The JWKS endpoint must only expose the public portion of the key.
    """
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    # Convert exponent and modulus to URL-safe base64 without padding.
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
    """
    Create the database and keys table if they do not already exist.

    If the table is empty, seed it with:
    - one expired key
    - one valid (unexpired) key

    This ensures the /auth endpoint can be tested in both normal
    and expired-key modes.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

        cursor.execute("SELECT COUNT(*) FROM keys")
        count = cursor.fetchone()[0]

        # Only insert starter keys if the table is currently empty.
        if count == 0:
            now = int(time.time())

            expired_key_pem = generate_key_pem()
            valid_key_pem = generate_key_pem()

            # Insert one expired key.
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (expired_key_pem, now - 3600),
            )

            # Insert one valid key.
            cursor.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (valid_key_pem, now + 3600),
            )

        conn.commit()


@app.get("/.well-known/jwks.json")
def jwks():
    """
    Return all valid (non-expired) public keys in JWKS format.

    Only unexpired keys should be exposed here.
    """
    now = int(time.time())

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Select all keys whose expiration time is still in the future.
        cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (now,))
        rows = cursor.fetchall()

    keys = []
    for kid, pem_data, _exp in rows:
        private_key = load_private_key_from_pem(pem_data)
        keys.append(rsa_to_jwk(private_key, kid))

    return {"keys": keys}


@app.post("/auth")
def auth(expired: bool = Query(False)):
    """
    Sign and return a JWT using either:
    - a valid key if expired=False
    - an expired key if expired=True
    """
    now = int(time.time())

    with get_db_connection() as conn:
        cursor = conn.cursor()

        if expired:
            # Read one expired key from the database.
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1",
                (now,),
            )
        else:
            # Read one valid key from the database.
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1",
                (now,),
            )

        row = cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="No suitable key found")

    kid, pem_data, expiry = row
    private_key = load_private_key_from_pem(pem_data)

    # Mock user payload expected by the grading client.
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

    return {"token": token}


# Initialize the database as soon as the application starts.
init_db()