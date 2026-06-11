"""
dashboard.py — Cerverus Swarm: Web Dashboard
=============================================
A Flask web application that displays the swarm's activity,
vulnerability findings, ontology state, and cycle history.

Runs on port 8080, separate from the target app (port 5000).
Reads data from config/ directory (read-only).
"""

import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, send_from_directory

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.urandom(32).hex()

# ── Config paths ────────────────────────────────────────────────────
CONFIG_DIR = Path(os.getenv("CONFIG_DIR", "./config"))
REPORT_PATH = CONFIG_DIR / "last_audit_report.json"
ONTOLOGY_PATH = CONFIG_DIR / "ontology.json"
HISTORY_PATH = CONFIG_DIR / "cycle_history.json"


def _read_json(path: Path):
    """Safely read a JSON file, returning None if it doesn't exist or is invalid."""
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


# ── Routes ──────────────────────────────────────────────────────────


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/report")
def api_report():
    """Return the latest audit report as JSON."""
    data = _read_json(REPORT_PATH)
    if data is None:
        return jsonify({"error": "No audit report found. Run the swarm first."}), 404
    return jsonify(data)


@app.route("/api/ontology")
def api_ontology():
    """Return the current ontology knowledge base as JSON."""
    data = _read_json(ONTOLOGY_PATH)
    if data is None:
        return jsonify({"error": "No ontology file found."}), 404
    return jsonify(data)


@app.route("/api/history")
def api_history():
    """Return the cycle history as JSON."""
    data = _read_json(HISTORY_PATH)
    if data is None:
        return jsonify([])
    return jsonify(data)


@app.route("/api/health")
def api_health():
    """Simple health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "cerverus-dashboard",
        "report_exists": REPORT_PATH.exists(),
        "ontology_exists": ONTOLOGY_PATH.exists(),
        "history_exists": HISTORY_PATH.exists(),
    })


# ── Entry Point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    print(f"\n  Cerverus Dashboard starting on http://localhost:{port}")
    print(f"   Config dir: {CONFIG_DIR.resolve()}")
    print(f"   Report: {' Found' if REPORT_PATH.exists() else ' Not found'}")
    print(f"   Ontology: {' Found' if ONTOLOGY_PATH.exists() else ' Not found'}")
    app.run(host="0.0.0.0", port=port, debug=False)
