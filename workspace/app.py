"""
workspace/app.py — Patched Flask Application
=============================================================
This is the patched version of the Cerverus Target App with security vulnerabilities fixed.

Vulnerabilities addressed:
  1. Information Exposure (Password Hashes) -> removed password hash from search results
  2. Hardcoded Credentials -> replaced with environment variable-based passwords
  3. Session Cookie Misconfiguration -> added HttpOnly and Secure flags
  4. Rate Limiting Bypass (Multi-Worker) -> moved to shared database storage
  5. Resource Exhaustion (Memory Leak) -> implemented periodic cleanup in DB
  6. Inconsistent Secret Key -> made SECRET_KEY persistent across restarts in debug mode
  7. SQL Injection -> already fixed via parameterized queries
  8. Reflected XSS -> already fixed via input escaping
  9. Hardcoded secret key -> already fixed via environment variable
  10. Debug mode in production -> already fixed via environment variable
  11. Missing CSRF protection -> already fixed via CSRF tokens
  12. Verbose error messages -> already fixed via generic responses
  13. Sensitive config exposure -> already fixed via debug-only endpoint
  14. Missing HTTP security headers -> already fixed via after_request hook
  15. Missing rate limiting -> now implemented with shared storage
  16. Insecure service binding -> already fixed via debug-mode localhost binding
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
# Use environment variable for secret key with persistent fallback in debug mode
secret_key = os.environ.get("SECRET_KEY")
if secret_key is None:
    if app.config.get("DEBUG", False):
        # In debug mode, use a fixed key for consistency across restarts
        [REDACTED]
        app.logger.warning(
            "Using default SECRET_KEY for development. "
            "Set SECRET_KEY environment variable for production."
        )
    else:
        raise RuntimeError("SECRET_KEY must be set in production")
app.config["SECRET_KEY"] = secret_key
# Control debug mode via environment variable (default: False for safety)
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "t")
# Session cookie security settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = not app.config["DEBUG"]  # Secure only in production

# ── Database Configuration ───────────────────────────────────────────
# Use file-based database for shared state between workers
DATABASE = os.environ.get("DATABASE_URL", "cerverus.db")

# ── Database helpers ────────────────────────────────────────────────
def get_db():
    """Get or create a database connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        _init_db(db)
    return db


def _init_db(db):
    """Seed the database with sample data and create necessary tables."""
    # Create users table
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
    # Create login attempts table for rate limiting
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            attempt_time REAL NOT NULL
        )
    """
    )
    # Create index for efficient rate limiting lookups
    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time 
        ON login_attempts (ip, attempt_time)
    """
    )
    
    # Insert sample users with passwords from environment variables
    users = [
        ("alice", "alice@example.com", "user", os.environ.get("ALICE_PASSWORD")),
        ("bob", "bob@example.com", "user", os.environ.get("BOB_PASSWORD")),
        ("admin", "admin@cerverus.local", "admin", os.environ.get("ADMIN_PASSWORD"))
    ]
    for username, email, role, password in users:
        if password is None:
            # Generate a random password if not set via environment variable
            password = secrets.token_urlsafe(16)
            if app.config["DEBUG"]:
                app.logger.warning(
                    f"Generated temporary password for {username}: {password}. "
                    "Set {username.upper()}_PASSWORD environment variable for production."
                )
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
    - Rate limiting using shared database storage
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

    ip = request.remote_addr
    current_time = time.time()
    db = get_db()
    
    try:
        # Clean up old login attempts (older than 1 minute)
        db.execute(
            "DELETE FROM login_attempts WHERE attempt_time < ?",
            (current_time - 60,)
        )
        
        # Check rate limit: count attempts in last minute
        cursor = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE ip = ?",
            (ip,)
        )
        attempt_count = cursor.fetchone()[0]
        
        if attempt_count >= 5:
            return jsonify({"error": "Too many login attempts. Please try again later."}), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Parameterized query to prevent SQL injection
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", 
            (username,)
        ).fetchone()
        
        if user and check_password_hash(user['password'], password):
            # Successful login: reset rate limit for this IP
            db.execute(
                "DELETE FROM login_attempts WHERE ip = ?",
                (ip,)
            )
            db.commit()
            session['csrf_token'] = secrets.token_hex(16)  # Rotate token
            return jsonify({"message": "Login successful", "role": user['role']}), 200
        else:
            # Failed login: record attempt
            db.execute(
                "INSERT INTO login_attempts (ip, attempt_time) VALUES (?, ?)",
                (ip, current_time)
            )
            db.commit()
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        # Generic error message to avoid information leakage
        return jsonify({"error": "Authentication error"}), 500


@app.route("/search")
def search_users():
    """
    Fixed search route with:
    - Parameterized queries to prevent SQL injection
    - Exclusion of sensitive fields (password hash) from results
    """
    name = request.args.get("name", "")

    # Parameterized query to prevent SQL injection
    query = "SELECT id, username, email, role FROM users WHERE username = ?"
    
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