"""
main.py — Cerverus Swarm: Agent Orchestration (Single-Pass Mode)
================================================================
Entrypoint for the DevSecOps evaluation loop.

Flow:
  1. Builder Agent  → reads workspace/app.py
  2. Red Team Agent → audits code for vulnerabilities
  3. Blue Team Agent → proposes patches & updates ontology knowledge base

Uses camel-ai ChatAgent with OpenRouter (Nemotron 3 Super Free).
"""

import json
import os
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


# ── Agent Definitions ───────────────────────────────────────────────

# System prompts that define each agent's role and behavior

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

Be exhaustive. Check for OWASP Top 10, CWE common weaknesses, and any
security anti-patterns. Missing a vulnerability means it ships to production."""

BLUE_TEAM_SYSTEM_PROMPT = """You are the Blue Team Agent (Defender/Reviewer) in the Cerverus DevSecOps Swarm.

Your role:
- You receive the Red Team's vulnerability report.
- For each vulnerability, you propose a concrete, production-ready fix.
- You also produce an ontology update entry for the knowledge base.

For each vulnerability fix, provide:
1. VULNERABILITY ID - Matching the Red Team's ID
2. FIX DESCRIPTION - What needs to change and why
3. PATCHED CODE - The exact corrected code snippet (ready to paste)
4. PREVENTION RULE - A general rule to add to the ontology so this
   class of vulnerability is caught automatically in future builds.

Output a final section called ONTOLOGY UPDATE with a JSON array of
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


# We use Hermes Guardian to create and dispatch agents.


# ── Main Orchestration Loop (Single-Pass) ───────────────────────────


def run_single_pass():
    """
    Execute one complete Builder → Red Team → Blue Team cycle.

    This is the core DevSecOps evaluation loop:
    1. Builder analyzes the target code
    2. Red Team audits for vulnerabilities
    3. Blue Team proposes fixes and updates the ontology
    """
    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — DevSecOps Evaluation Loop")
    print("█  Mode: Single-Pass")
    print(f"█  Time: {datetime.now(timezone.utc).isoformat()}")
    print("█" * 60)

    # ── Step 0: Validate environment
    validate_env()

    # ── Step 1: Load inputs
    source_code = read_target_code()
    ontology = load_ontology()

    known_vulns = ontology[0].get("known_vulnerabilities", [])
    print(f" Ontology: {len(known_vulns)} known vulnerabilities")

    # ── Step 2: Initialize Hermes Guardian
    hermes = HermesGuardian()

    # Create the camel-ai agents via Hermes
    builder_agent = hermes.create_agent("Builder Agent", BUILDER_SYSTEM_PROMPT)
    red_team_agent = hermes.create_agent("Red Team Agent", RED_TEAM_SYSTEM_PROMPT)
    blue_team_agent = hermes.create_agent("Blue Team Agent", BLUE_TEAM_SYSTEM_PROMPT)

    # ── Step 3: Builder Agent — Analyze the code
    builder_input = f"""Analyze the following Python source code:

```python
{source_code}
```

Provide a thorough structural analysis."""

    builder_output = hermes.dispatch(
        builder_agent, builder_input, "Builder Agent"
    )
    print(f"\n📋 Builder Analysis Preview:\n{builder_output[:500]}...\n")

    # ── Step 4: Red Team Agent — Find vulnerabilities
    red_team_input = f"""Here is the source code to audit:

```python
{source_code}
```

And here is the Builder Agent's structural analysis:

{builder_output}

Previously known vulnerabilities in our ontology:
{json.dumps(known_vulns, indent=2) if known_vulns else "None — this is the first audit."}

Perform a complete security audit. Find ALL vulnerabilities."""

    red_team_output = hermes.dispatch(
        red_team_agent, red_team_input, "Red Team Agent"
    )
    print(f"\n🔴 Red Team Report Preview:\n{red_team_output[:500]}...\n")

    # ── Step 5: Blue Team Agent — Propose fixes & update ontology
    blue_team_input = f"""Here is the Red Team's vulnerability report:

{red_team_output}

And here is the original source code:

```python
{source_code}
```

For each vulnerability:
1. Propose a concrete, production-ready fix with patched code.
2. Create a prevention rule for the ontology knowledge base.
3. Output the ONTOLOGY UPDATE JSON at the end."""

    blue_team_output = hermes.dispatch(
        blue_team_agent, blue_team_input, "Blue Team Agent"
    )
    print(f"\n🔵 Blue Team Report Preview:\n{blue_team_output[:500]}...\n")

    # ── Step 6: Update the ontology with new rules
    try:
        # Try to extract the JSON ontology update from the Blue Team's output
        json_start = blue_team_output.rfind("[")
        json_end = blue_team_output.rfind("]") + 1
        if json_start != -1 and json_end > json_start:
            new_rules = json.loads(blue_team_output[json_start:json_end])
            ontology[0]["known_vulnerabilities"].extend(new_rules)
            ontology[0]["system_state"] = "audited"
            ontology[0]["last_audit"] = datetime.now(timezone.utc).isoformat()
            ontology[0]["audit_model"] = OPENROUTER_MODEL_ID
            save_ontology(ontology)
            print(f"\n Added {len(new_rules)} new rules to ontology")
        else:
            print("\n  Could not extract ontology rules from Blue Team output")
    except json.JSONDecodeError as e:
        print(f"\n  Failed to parse ontology JSON: {e}")

    # ── Step 7: Save the full audit report
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": OPENROUTER_MODEL_ID,
        "target": TARGET_APP_PATH,
        "builder_analysis": builder_output,
        "red_team_report": red_team_output,
        "blue_team_report": blue_team_output,
    }

    report_path = Path("./config/last_audit_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f" Full audit report saved: {report_path}")

    # ── Done
    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — Cycle Complete")
    print("█" * 60)
    print("\nNext steps:")
    print("  • Review the Blue Team's patches in the audit report")
    print("  • Apply approved patches to workspace/app.py")
    print("  • Re-run to verify fixes (future: cyclical mode)")


# ── Entry Point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    run_single_pass()
