"""
main.py — Cerverus Swarm: Agent Orchestration
===============================================
Entrypoint for the DevSecOps evaluation loop.

Modes:
  --mode single    (default) One Builder → Red Team → Blue Team pass
  --mode cyclical  Auto-patch and re-scan up to MAX_CYCLES iterations

Flow per cycle:
  1. Builder Agent  → reads workspace/app.py
  2. Red Team Agent → audits code for vulnerabilities
  3. Blue Team Agent → proposes patches & updates ontology knowledge base
  4. (cyclical only) Apply patches → repeat until 0 vulns or max cycles

Uses camel-ai ChatAgent with OpenRouter (Nemotron 3 Super Free).
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

# ── Load environment ────────────────────────────────────────────────
load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL_ID = os.getenv(
    "OPENROUTER_MODEL_ID", "nvidia/nemotron-3-super-120b-a12b:free"
)
ONTOLOGY_PATH = os.getenv("OWL_ONTOLOGY_PATH", "./config/ontology.json")
TARGET_APP_PATH = os.getenv("TARGET_APP_PATH", "./workspace/app.py")
MAX_CYCLES = int(os.getenv("MAX_CYCLES", "5"))
CYCLE_HISTORY_PATH = os.getenv("CYCLE_HISTORY_PATH", "./config/cycle_history.json")


from hermes_guardian import HermesGuardian


def validate_env():
    """Ensure required environment variables are set."""
    if not OPENROUTER_API_KEY or OPENROUTER_API_KEY == "your_openrouter_api_key_here":
        print("❌ ERROR: OPENROUTER_API_KEY is not set in .env")
        print("   Please add your OpenRouter API key to the .env file.")
        sys.exit(1)
    print(f"✅ API Key loaded (ends with ...{OPENROUTER_API_KEY[-6:]})")
    print(f"✅ Model: {OPENROUTER_MODEL_ID}")


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
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


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
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
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

    The Blue Team is expected to output a code block with the complete
    patched file. We look for the largest Python code block in the output.
    """
    # Find all Python code blocks in the output
    code_blocks = re.findall(
        r"```(?:python)?\s*\n(.*?)```",
        blue_team_output,
        re.DOTALL
    )

    if not code_blocks:
        print("  ⚠️  No code blocks found in Blue Team output. Skipping patch.")
        return False

    # Use the longest code block (most likely the full patched file)
    patched_code = max(code_blocks, key=len).strip()

    # Sanity check: the patched code should look like a Python file
    if len(patched_code) < 50 or "flask" not in patched_code.lower():
        print("  ⚠️  Extracted code doesn't look like a valid Flask app. Skipping patch.")
        return False

    # Back up the current version before overwriting
    backup_target(cycle_number)

    # Write the patched code
    path = Path(TARGET_APP_PATH)
    path.write_text(patched_code, encoding="utf-8")
    print(f"  ✅ Patched {path.name} ({len(patched_code)} chars)")
    return True


def count_vulnerabilities(red_team_output: str) -> int:
    """
    Count the number of vulnerability IDs (VULN-XXX) in the Red Team's report.
    Returns 0 if no vulnerabilities are found.
    """
    matches = re.findall(r"VULN-\d{3}", red_team_output)
    # Deduplicate (same VULN ID may be mentioned multiple times)
    unique = set(matches)
    return len(unique)


# ── Agent Definitions ───────────────────────────────────────────────

BUILDER_SYSTEM_PROMPT = """You are the Builder Agent in the Cerverus DevSecOps Swarm.

Your role:
- You receive source code from the workspace.
- You analyze the code structure, purpose, and architecture.
- You produce a clear, structured summary of what the code does,
  including all endpoints, data flows, and configurations.

Output format:
Provide a structured analysis with these sections:
1. APPLICATION OVERVIEW - What the app does
2. ENDPOINTS - List each route with method, path, and purpose
3. DATA FLOW - How data moves through the application
4. CONFIGURATIONS - All config values and settings
5. DEPENDENCIES - Libraries and modules used

Be thorough. The Red Team Agent will use your analysis to find vulnerabilities."""

RED_TEAM_SYSTEM_PROMPT = """You are the Red Team Agent (Attacker/Evaluator) in the Cerverus DevSecOps Swarm.

Your role:
- You receive source code AND the Builder Agent's analysis.
- You perform a thorough security audit looking for vulnerabilities.
- You think like an attacker: how would you exploit this code?

For each vulnerability found, report:
1. VULNERABILITY ID - Sequential (VULN-001, VULN-002, etc.)
2. TYPE - Category (e.g., SQL Injection, XSS, Hardcoded Credentials)
3. SEVERITY - Critical / High / Medium / Low
4. LOCATION - Exact function/route and line description
5. DESCRIPTION - What the vulnerability is
6. EXPLOIT SCENARIO - How an attacker would exploit it
7. EVIDENCE - The specific code snippet that is vulnerable

If the code has NO vulnerabilities, explicitly state:
"CLEAN SCAN: No vulnerabilities detected."

Be exhaustive. Check for OWASP Top 10, CWE common weaknesses, and any
security anti-patterns. Missing a vulnerability means it ships to production."""

BLUE_TEAM_SYSTEM_PROMPT = """You are the Blue Team Agent (Defender/Reviewer) in the Cerverus DevSecOps Swarm.

Your role:
- You receive the Red Team's vulnerability report.
- For each vulnerability, you propose a concrete, production-ready fix.
- You also produce an ontology update entry for the knowledge base.

CRITICAL: You MUST output the COMPLETE patched version of the entire source file
in a single Python code block. Do not output partial snippets — output the full file
with ALL fixes applied, so it can be saved directly as the new app.py.

For each vulnerability fix, provide:
1. VULNERABILITY ID - Matching the Red Team's ID
2. FIX DESCRIPTION - What needs to change and why
3. PREVENTION RULE - A general rule to add to the ontology

Then output the complete patched file:
```python
# ... the entire patched source code here ...
```

Finally, output a section called ONTOLOGY UPDATE with a JSON array of
new rules to add to the knowledge base, formatted as:
```json
[
  {
    "rule_id": "RULE-001",
    "vulnerability_class": "SQL Injection",
    "prevention": "Always use parameterized queries",
    "severity": "Critical",
    "detected_at": "<timestamp>"
  }
]
```

Your patches must be secure, follow best practices, and not break functionality."""


# ── Core Cycle Function ─────────────────────────────────────────────


def run_cycle(hermes: HermesGuardian, cycle_number: int, total_cycles: int) -> dict:
    """
    Execute one complete Builder → Red Team → Blue Team cycle.
    Returns a dict with the cycle results.
    """
    print(f"\n{'━'*60}")
    print(f"  CYCLE {cycle_number}/{total_cycles}")
    print(f"{'━'*60}")

    # ── Step 1: Load inputs
    source_code = read_target_code()
    ontology = load_ontology()
    known_vulns = ontology[0].get("known_vulnerabilities", [])
    print(f" Ontology: {len(known_vulns)} known rules")

    # ── Step 2: Create agents
    builder_agent = hermes.create_agent("Builder Agent", BUILDER_SYSTEM_PROMPT)
    red_team_agent = hermes.create_agent("Red Team Agent", RED_TEAM_SYSTEM_PROMPT)
    blue_team_agent = hermes.create_agent("Blue Team Agent", BLUE_TEAM_SYSTEM_PROMPT)

    # ── Step 3: Builder Agent
    builder_input = f"""Analyze the following Python source code:

```python
{source_code}
```

Provide a thorough structural analysis."""

    builder_output = hermes.dispatch(builder_agent, builder_input, "Builder Agent")
    print(f"\n📋 Builder Analysis Preview:\n{builder_output[:500]}...\n")

    # ── Step 4: Red Team Agent
    red_team_input = f"""Here is the source code to audit:

```python
{source_code}
```

And here is the Builder Agent's structural analysis:

{builder_output}

Previously known vulnerabilities in our ontology:
{json.dumps(known_vulns, indent=2) if known_vulns else "None — this is the first audit."}

Perform a complete security audit. Find ALL vulnerabilities.
If the code is clean, state "CLEAN SCAN: No vulnerabilities detected." """

    red_team_output = hermes.dispatch(red_team_agent, red_team_input, "Red Team Agent")
    print(f"\n🔴 Red Team Report Preview:\n{red_team_output[:500]}...\n")

    vuln_count = count_vulnerabilities(red_team_output)
    is_clean = "CLEAN SCAN" in red_team_output.upper() or vuln_count == 0
    print(f"   Vulnerabilities found: {vuln_count}")

    # ── Step 5: Blue Team Agent (skip if clean scan)
    blue_team_output = ""
    patch_applied = False

    if not is_clean:
        blue_team_input = f"""Here is the Red Team's vulnerability report:

{red_team_output}

And here is the original source code:

```python
{source_code}
```

For each vulnerability:
1. Propose a concrete, production-ready fix.
2. Create a prevention rule for the ontology knowledge base.
3. Output the COMPLETE PATCHED FILE in a single Python code block.
4. Output the ONTOLOGY UPDATE JSON at the end."""

        blue_team_output = hermes.dispatch(blue_team_agent, blue_team_input, "Blue Team Agent")
        print(f"\n🔵 Blue Team Report Preview:\n{blue_team_output[:500]}...\n")

        # ── Step 6: Update the ontology with new rules
        try:
            json_start = blue_team_output.rfind("[")
            json_end = blue_team_output.rfind("]") + 1
            if json_start != -1 and json_end > json_start:
                new_rules = json.loads(blue_team_output[json_start:json_end])
                ontology[0]["known_vulnerabilities"].extend(new_rules)
                ontology[0]["system_state"] = "audited"
                ontology[0]["last_audit"] = datetime.now(timezone.utc).isoformat()
                ontology[0]["audit_model"] = OPENROUTER_MODEL_ID
                ontology[0]["audit_cycle"] = cycle_number
                save_ontology(ontology)
                print(f"\n Added {len(new_rules)} new rules to ontology")
            else:
                print("\n  Could not extract ontology rules from Blue Team output")
        except json.JSONDecodeError as e:
            print(f"\n  Failed to parse ontology JSON: {e}")

        # ── Step 7: Apply patches (cyclical mode will use this)
        patch_applied = apply_patches(blue_team_output, cycle_number)
    else:
        print("\n🎉 CLEAN SCAN — No vulnerabilities detected! Skipping Blue Team.")

    # ── Build cycle result
    cycle_result = {
        "cycle": cycle_number,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": OPENROUTER_MODEL_ID,
        "vulnerabilities_found": vuln_count,
        "is_clean": is_clean,
        "patch_applied": patch_applied,
        "builder_preview": builder_output[:300],
        "red_team_preview": red_team_output[:300],
        "blue_team_preview": blue_team_output[:300] if blue_team_output else "Skipped (clean scan)",
        "hermes_sanitization_events": hermes.get_sanitization_report(),
    }

    return cycle_result


# ── Orchestration Modes ─────────────────────────────────────────────


def run_single_pass():
    """Execute one complete Builder → Red Team → Blue Team cycle."""
    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — DevSecOps Evaluation Loop")
    print("█  Mode: Single-Pass")
    print(f"█  Time: {datetime.now(timezone.utc).isoformat()}")
    print("█" * 60)

    validate_env()
    hermes = HermesGuardian()

    result = run_cycle(hermes, cycle_number=1, total_cycles=1)

    # Save the full audit report
    report = {
        "mode": "single-pass",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": OPENROUTER_MODEL_ID,
        "cycles": [result],
    }
    report_path = Path("./config/last_audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f" Full audit report saved: {report_path}")

    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — Cycle Complete")
    print("█" * 60)


def run_cyclical():
    """
    Execute the DevSecOps loop repeatedly until either:
      - The Red Team finds 0 vulnerabilities (clean scan), or
      - MAX_CYCLES is reached.
    """
    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — DevSecOps Evaluation Loop")
    print(f"█  Mode: Cyclical (max {MAX_CYCLES} iterations)")
    print(f"█  Time: {datetime.now(timezone.utc).isoformat()}")
    print("█" * 60)

    validate_env()
    hermes = HermesGuardian()

    # Back up the original file as v0 before any patches
    backup_target(0)

    cycle_history = load_cycle_history()
    run_start = datetime.now(timezone.utc).isoformat()

    for cycle_num in range(1, MAX_CYCLES + 1):
        result = run_cycle(hermes, cycle_number=cycle_num, total_cycles=MAX_CYCLES)
        cycle_history.append(result)
        save_cycle_history(cycle_history)

        if result["is_clean"]:
            print(f"\n🎉 Code is CLEAN after {cycle_num} cycle(s)!")
            break

        if not result["patch_applied"] and not result["is_clean"]:
            print(f"\n⚠️  Blue Team could not produce a valid patch. Stopping.")
            break

        if cycle_num < MAX_CYCLES:
            print(f"\n🔄 Vulnerabilities remain. Starting cycle {cycle_num + 1}...")
    else:
        print(f"\n⚠️  Reached maximum of {MAX_CYCLES} cycles. Some vulnerabilities may remain.")

    # Save the full audit report
    report = {
        "mode": "cyclical",
        "timestamp": run_start,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "model": OPENROUTER_MODEL_ID,
        "max_cycles": MAX_CYCLES,
        "cycles_completed": len([c for c in cycle_history if c.get("timestamp", "") >= run_start]),
        "final_clean": cycle_history[-1]["is_clean"] if cycle_history else False,
        "cycles": cycle_history,
    }
    report_path = Path("./config/last_audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f" Full audit report saved: {report_path}")

    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — All Cycles Complete")
    print(f"█  Total cycles: {len(cycle_history)}")
    print(f"█  Final status: {'✅ CLEAN' if report['final_clean'] else '⚠️  VULNERABILITIES REMAIN'}")
    print("█" * 60)


# ── Entry Point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cerverus Swarm — DevSecOps Agent Orchestration")
    parser.add_argument(
        "--mode",
        choices=["single", "cyclical"],
        default="single",
        help="Execution mode: 'single' for one pass, 'cyclical' for auto-patch loop (default: single)"
    )
    args = parser.parse_args()

    if args.mode == "cyclical":
        run_cyclical()
    else:
        run_single_pass()
