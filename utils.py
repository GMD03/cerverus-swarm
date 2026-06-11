"""
utils.py — Cerverus Swarm: Core Utilities
=========================================
File I/O, parsing, environment validation, and patching logic.
"""

import json
import os
import re
import shutil
import sys
from pathlib import Path

from dotenv import load_dotenv

# ── Load environment ────────────────────────────────────────────────
load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL_ID = os.getenv("OPENROUTER_MODEL_ID", "nvidia/nemotron-3-super-120b-a12b:free")
ONTOLOGY_PATH = os.getenv("OWL_ONTOLOGY_PATH", "./config/ontology.json")
TARGET_APP_PATH = os.getenv("TARGET_APP_PATH", "./workspace/app.py")
MAX_CYCLES = int(os.getenv("MAX_CYCLES", "5"))
CYCLE_HISTORY_PATH = os.getenv("CYCLE_HISTORY_PATH", "./config/cycle_history.json")

HERMES_GATEWAY = os.getenv("HERMES_GATEWAY_URL", "http://127.0.0.1:8642")
HERMES_API_KEY = os.getenv("HERMES_API_KEY", "")


def validate_env():
    """Ensure required environment variables are set."""
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == "your_openrouter_api_key_here":
        print(" ERROR: OPENROUTER_API_KEY is not set in .env")
        print("   Please add your OpenRouter API key to the .env file.")
        sys.exit(1)
    print(f" API Key loaded (ends with ...{OPENROUTER_API_KEY[-6:]})")
    print(f" Model: {OPENROUTER_MODEL_ID}")


# ── File I/O helpers ────────────────────────────────────────────────

def read_target_code() -> str:
    """Read the vulnerable target application source code."""
    path = Path(TARGET_APP_PATH)
    if not path.exists():
        print(f" ERROR: Target app not found at {path.resolve()}")
        sys.exit(1)
    code = path.read_text(encoding="utf-8")
    print(f" Loaded target: {path.name} ({len(code)} chars, {code.count(chr(10))+1} lines)")
    return code


def load_ontology() -> list:
    """Load the current ontology knowledge base."""
    path = Path(ONTOLOGY_PATH)
    if not path.exists():
        return [{"system_state": "initialized", "known_vulnerabilities": []}]
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return [{"system_state": "initialized", "known_vulnerabilities": []}]


def save_ontology(ontology: list):
    """Persist updated ontology back to disk."""
    path = Path(ONTOLOGY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ontology, f, indent=2)
    print(f" Ontology updated: {path}")


def load_cycle_history() -> list:
    """Load existing cycle history or create a new one."""
    path = Path(CYCLE_HISTORY_PATH)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return []


def save_cycle_history(history: list):
    """Persist cycle history to disk."""
    path = Path(CYCLE_HISTORY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def backup_target(cycle_number: int):
    """Create a versioned backup of the target app before patching."""
    src = Path(TARGET_APP_PATH)
    dst = src.with_suffix(f".py.v{cycle_number}")
    shutil.copy2(src, dst)
    print(f" Backup saved: {dst.name}")


def apply_patches(blue_team_output: str, cycle_number: int) -> bool:
    """
    Extract the full patched code from the Blue Team's output and write it
    to workspace/app.py. Returns True if patching succeeded.
    """
    code_blocks = re.findall(
        r"```(?:python)?\s*\n(.*?)```",
        blue_team_output,
        re.DOTALL
    )

    if not code_blocks:
        print("    No code blocks found in Blue Team output. Skipping patch.")
        return False

    patched_code = max(code_blocks, key=len).strip()

    if len(patched_code) < 50 or "flask" not in patched_code.lower():
        print("    Extracted code doesn't look like a valid Flask app. Skipping patch.")
        return False

    backup_target(cycle_number)

    path = Path(TARGET_APP_PATH)
    path.write_text(patched_code, encoding="utf-8")
    print(f"   Patched {path.name} ({len(patched_code)} chars)")
    return True


def count_vulnerabilities(red_team_output: str) -> int:
    """
    Count the number of vulnerability IDs (VULN-XXX) in the Red Team's report.
    Returns 0 if no vulnerabilities are found.
    """
    matches = re.findall(r"VULN-\d{3}", red_team_output)
    unique = set(matches)
    return len(unique)
