# Project 2 - Extending the JWKS Server

## Overview
This project extends a JWKS server by using a SQLite database to store RSA private keys. The server signs JWTs using keys stored in the database and exposes valid public keys through a JWKS endpoint.

## Features
- SQLite-backed key storage
- Stores one expired key and one valid key
- `POST /auth` signs a JWT with a valid or expired key
- `GET /.well-known/jwks.json` returns all valid public keys in JWKS format
- Parameterized SQL queries to reduce SQL injection risk
- Test suite with coverage

## Database
The SQLite database file is named `totally_not_my_privateKeys.db`.

The database table schema is:

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)