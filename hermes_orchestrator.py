"""
hermes_orchestrator.py — Cerverus Swarm: Hermes Desktop Integration
===================================================================
Connects to the Hermes API Gateway to dispatch the orchestrator skill,
offloading the orchestration to the Hermes Agent platform.
"""

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from utils import (
    validate_env, read_target_code, load_ontology, save_ontology,
    backup_target, apply_patches, count_vulnerabilities,
    HERMES_GATEWAY, HERMES_API_KEY
)
from hermes_guardian import HermesGuardian
from camel_orchestrator import run_single_pass


def run_hermes():
    """Execute the DevSecOps loop via the Hermes Agent API Gateway."""
    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — DevSecOps Evaluation Loop")
    print("█  Mode: Hermes Desktop Integration")
    print(f"█  Gateway: {HERMES_GATEWAY}")
    print(f"█  Time: {datetime.now(timezone.utc).isoformat()}")
    print("█" * 60)

    validate_env()

    # Check if Hermes gateway is reachable
    try:
        health_req = urllib.request.Request(f"{HERMES_GATEWAY}/v1/models")
        if HERMES_API_KEY:
            health_req.add_header("Authorization", f"Bearer {HERMES_API_KEY}")
        urllib.request.urlopen(health_req, timeout=5)
        print(" Hermes Agent gateway is reachable")
    except (urllib.error.URLError, OSError) as e:
        print(f"  Cannot reach Hermes gateway at {HERMES_GATEWAY}: {e}")
        print("   Falling back to standalone (camel-ai) mode...")
        run_single_pass()
        return

    # Load the target code and ontology for the prompt
    source_code = read_target_code()
    ontology = load_ontology()
    known_vulns = ontology[0].get("known_vulnerabilities", [])

    # Build the orchestration prompt
    hermes_prompt = f"""Run the Cerverus DevSecOps security loop on the following Python source code.

Execute these steps in order:
1. BUILDER: Analyze the code structure (endpoints, data flows, configs)
2. RED TEAM: Perform a full OWASP Top 10 security audit. List all vulnerabilities as VULN-001, VULN-002, etc.
3. BLUE TEAM: For each vulnerability, write a production-ready fix. Output the COMPLETE patched file in a Python code block. Output ONTOLOGY UPDATE rules as JSON.

Source code to audit:

```python
{source_code}
```

Known ontology rules (do not re-report these):
{json.dumps(known_vulns[:5], indent=2) if known_vulns else "None — first audit."}

IMPORTANT: Output the complete patched file and ontology JSON at the end."""

    # Initialize Hermes Guardian for sanitization
    hermes = HermesGuardian()
    safe_prompt = hermes.sanitize(hermes_prompt)

    # Send to Hermes API Gateway (OpenAI-compatible endpoint)
    payload = json.dumps({
        "model": "hermes",
        "messages": [
            {"role": "user", "content": safe_prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 8192,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
    }
    if HERMES_API_KEY:
        headers["Authorization"] = f"Bearer {HERMES_API_KEY}"

    req = urllib.request.Request(
        f"{HERMES_GATEWAY}/v1/chat/completions",
        data=payload,
        headers=headers,
        method="POST",
    )

    print("\n >>> Dispatching to Hermes Agent via gateway...")

    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            content = result["choices"][0]["message"]["content"]

            # Sanitize the response
            safe_content = hermes.sanitize(content)
            print(f"  Hermes Agent completed ({len(safe_content)} chars)")

            # Try to extract and apply patches
            vuln_count = count_vulnerabilities(safe_content)
            print(f"   Vulnerabilities found: {vuln_count}")

            if vuln_count > 0:
                backup_target(0)
                apply_patches(safe_content, 1)

                # Try to extract ontology rules
                try:
                    json_start = safe_content.rfind("[")
                    json_end = safe_content.rfind("]") + 1
                    if json_start != -1 and json_end > json_start:
                        new_rules = json.loads(safe_content[json_start:json_end])
                        ontology[0]["known_vulnerabilities"].extend(new_rules)
                        ontology[0]["system_state"] = "audited"
                        ontology[0]["last_audit"] = datetime.now(timezone.utc).isoformat()
                        ontology[0]["audit_model"] = "hermes-agent"
                        save_ontology(ontology)
                except (json.JSONDecodeError, IndexError):
                    print("   Could not extract ontology rules from Hermes output")

            # Save audit report
            report = {
                "mode": "hermes",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model": "hermes-agent (via gateway)",
                "cycles": [{
                    "cycle": 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "vulnerabilities_found": vuln_count,
                    "is_clean": vuln_count == 0,
                    "patch_applied": vuln_count > 0,
                    "builder_preview": safe_content[:300],
                    "red_team_preview": safe_content[:300],
                    "blue_team_preview": safe_content[:300],
                    "hermes_sanitization_events": hermes.get_sanitization_report(),
                }],
            }
            report_path = Path("./config/last_audit_report.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f" Full audit report saved: {report_path}")

    except urllib.error.HTTPError as e:
        print(f" Hermes gateway returned error {e.code}: {e.read().decode()}")
        print("   Falling back to standalone mode...")
        run_single_pass()
        return
    except Exception as e:
        print(f" Hermes gateway error: {e}")
        print("   Falling back to standalone mode...")
        run_single_pass()
        return

    print("\n" + "█" * 60)
    print("█  CERVERUS SWARM — Hermes Cycle Complete")
    print("█" * 60)
