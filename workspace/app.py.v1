"""
workspace/app.py — Deliberately Vulnerable Flask Application
=============================================================
This is the "target" application for the Cerverus Red Team Agent.
It contains INTENTIONAL security vulnerabilities for auditing purposes.

 !!!!! DO NOT deploy this code in production. Every flaw here is by design.

Vulnerabilities seeded:
  1. Hardcoded credentials (admin login)
  2. SQL Injection (user search)
  3. Reflected XSS (greeting endpoint)
  4. Hardcoded secret key (Flask config)
  5. Debug mode enabled in production
  6. No CSRF protection
  7. Verbose error messages exposing internals
"""

import sqlite3
import os
from flask import Flask, request, jsonify, g

# ── VULNERABILITY #4: Hardcoded secret key ──────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key-do-not-use"
app.config["DEBUG"] = True  # VULNERABILITY #5: Debug in production

# ── VULNERABILITY #1: Hardcoded credentials ─────────────────────────
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

DATABASE = ":memory:"


# ── Database helpers ────────────────────────────────────────────────
def get_db():
    """Get or create an in-memory SQLite database connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        _init_db(db)
    return db


def _init_db(db):
    """Seed the database with sample data."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """
    )
    db.execute(
        "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
        ("alice", "alice@example.com", "user"),
    )
    db.execute(
        "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
        ("bob", "bob@example.com", "user"),
    )
    db.execute(
        "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
        ("admin", "admin@cerverus.local", "admin"),
    )
    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ── Routes ──────────────────────────────────────────────────────────


@app.route("/")
def index():
    return jsonify(
        {
            "app": "Cerverus Target App",
            "status": "running",
            "version": "0.1.0-vulnerable",
        }
    )


@app.route("/login", methods=["POST"])
def login():
    """
    VULNERABILITY #1: Hardcoded credentials.
    Compares user input directly against plaintext constants.
    No hashing, no rate limiting, no account lockout.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return jsonify({"message": "Login successful", "role": "admin"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/search")
def search_users():
    """
    VULNERABILITY #2: SQL Injection.
    User input is interpolated directly into the SQL query string
    without parameterization or sanitization.
    """
    name = request.args.get("name", "")

    # !!! DANGEROUS: raw string interpolation in SQL
    query = f"SELECT * FROM users WHERE username = '{name}'"

    db = get_db()
    try:
        results = db.execute(query).fetchall()
        users = [dict(row) for row in results]
        return jsonify({"results": users})
    except Exception as e:
        # VULNERABILITY #7: Verbose error messages
        return jsonify({"error": str(e), "query": query}), 500


@app.route("/greet")
def greet():
    """
    VULNERABILITY #3: Reflected Cross-Site Scripting (XSS).
    User input is reflected directly into the response without
    escaping or sanitization.
    """
    name = request.args.get("name", "World")

    # !!! DANGEROUS: unsanitized user input in response
    return f"<h1>Hello, {name}!</h1>"


@app.route("/debug/config")
def debug_config():
    """
    VULNERABILITY #6: Sensitive config exposure.
    Exposes internal configuration including the secret key.
    No authentication required.
    """
    return jsonify(
        {
            "SECRET_KEY": app.config["SECRET_KEY"],
            "DEBUG": app.config["DEBUG"],
            "DATABASE": DATABASE,
            "ADMIN_USER": ADMIN_USERNAME,
        }
    )


# ── Entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
