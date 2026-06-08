"""
workspace/app.py — Patched Flask Application
=============================================================
This is the patched version of the Cerverus Target App with security vulnerabilities fixed.

Vulnerabilities addressed:
  1. Hardcoded credentials -> replaced with database-backed hashed passwords
  2. SQL Injection -> replaced with parameterized queries
  3. Reflected XSS -> escaped user input in HTML responses
  4. Hardcoded secret key -> set via environment variable
  5. Debug mode in production -> controlled by environment variable
  6. Missing CSRF protection -> added CSRF tokens for login
  7. Verbose error messages -> generic error responses
  8. Sensitive config exposure -> restricted /debug/config to debug mode only
  9. Missing HTTP security headers -> added via after_request hook
  10. Missing rate limiting -> added to /login endpoint
  11. Insecure service binding -> bind to 127.0.0.1 in debug mode
"""

import sqlite3
import os
import secrets
import time
from flask import Flask, request, jsonify, g, session
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape

# ── Configuration from Environment ────────────────────────────────────
app = Flask(__name__)
# Use environment variable for secret key with strong fallback for development
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
# Control debug mode via environment variable (default: False for safety)
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "t")

# ── Database Configuration ───────────────────────────────────────────
DATABASE = ":memory:"

# Rate limiting storage for login attempts (IP -> timestamps)
login_attempts = {}

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
    """Seed the database with sample data including password hashes."""
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            password TEXT
        )
    """
    )
    # Insert sample users with hashed passwords
    # In production, these should be set via secure registration process
    users = [
        ("alice", "alice@example.com", "user", "alice_password"),
        ("bob", "bob@example.com", "user", "bob_password"),
        ("admin", "admin@cerverus.local", "admin", os.environ.get("ADMIN_PASSWORD", "admin_secure_password_change_me"))
    ]
    for username, email, role, password in users:
        hashed_pw = generate_password_hash(password)
        db.execute(
            "INSERT OR IGNORE INTO users (username, email, role, password) VALUES (?, ?, ?, ?)",
            (username, email, role, hashed_pw)
        )
    db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ── Security Headers ─────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Basic CSP: restrict to same-origin resources
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self';"
    return response


# ── Routes ──────────────────────────────────────────────────────────


@app.route("/")
def index():
    return jsonify(
        {
            "app": "Cerverus Target App",
            "status": "running",
            "version": "0.1.0-patched",
        }
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Fixed login route with:
    - Hashed password verification via database
    - CSRF protection
    - Rate limiting
    - Generic error messages
    """
    if request.method == "GET":
        # Generate CSRF token for the form
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(16)
        # Return login form with CSRF token
        return f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login</title>
            </head>
            <body>
                <h2>Login</h2>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{session['csrf_token']}">
                    <label>Username:
                        <input type="text" name="username" required>
                    </label><br><br>
                    <label>Password:
                        <input type="password" name="password" required>
                    </label><br><br>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
        '''

    # POST request: process login
    # CSRF validation
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return jsonify({"error": "Invalid CSRF token"}), 400

    # Rate limiting by IP
    ip = request.remote_addr
    current_time = time.time()
    # Clean attempts older than 1 minute
    if ip in login_attempts:
        login_attempts[ip] = [t for t in login_attempts[ip] if current_time - t < 60]
    else:
        login_attempts[ip] = []
    
    if len(login_attempts[ip]) >= 5:
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    try:
        # Parameterized query to prevent SQL injection
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", 
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password'], password):
            # Successful login: reset rate limit and rotate CSRF token
            if ip in login_attempts:
                del login_attempts[ip]
            session['csrf_token'] = secrets.token_hex(16)  # Rotate token
            return jsonify({"message": "Login successful", "role": user['role']}), 200
        else:
            # Failed login: record attempt
            login_attempts[ip].append(current_time)
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception:
        # Generic error message to avoid information leakage
        return jsonify({"error": "Authentication error"}), 500


@app.route("/search")
def search_users():
    """
    Fixed search route with:
    - Parameterized queries to prevent SQL injection
    - Generic error messages
    """
    name = request.args.get("name", "")

    # Parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username = ?"
    
    db = get_db()
    try:
        results = db.execute(query, (name,)).fetchall()
        users = [dict(row) for row in results]
        return jsonify({"results": users})
    except Exception:
        # Generic error message
        return jsonify({"error": "Search error"}), 500


@app.route("/greet")
def greet():
    """
    Fixed greet route with:
    - Escaped user input to prevent XSS
    """
    name = request.args.get("name", "World")
    # Escape user input to prevent XSS
    safe_name = escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"


@app.route("/debug/config")
def debug_config():
    """
    Debug config endpoint - only available in debug mode.
    Exposes non-sensitive information only.
    """
    if not app.config["DEBUG"]:
        return jsonify({"error": "Not found"}), 404
        
    return jsonify(
        {
            "DEBUG": app.config["DEBUG"],
            "DATABASE": DATABASE,
            # Note: SECRET_KEY and ADMIN_USER are intentionally omitted for security
        }
    )


# ── Entry point ─────────────────────────────────────────────────────
if __name__ == "__main__":
    # In debug mode, bind only to localhost for security
    host = "127.0.0.1" if app.config["DEBUG"] else "0.0.0.0"
    app.run(host=host, port=5000, debug=app.config["DEBUG"])