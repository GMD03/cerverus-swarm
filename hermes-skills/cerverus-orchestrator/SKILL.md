---
name: cerverus-orchestrator
description: "Cerverus Orchestrator — Chains the Builder, Red Team, and Blue Team agents in sequence to run the full DevSecOps evaluation loop. Use when asked to 'run Cerverus', 'start the security scan', or 'execute the DevSecOps loop'."
version: 1.0.0
author: Cerverus Swarm
metadata:
  hermes:
    tags: [security, devsecops, orchestration, cerverus, workflow]
    related_skills: [cerverus-builder, cerverus-red-team, cerverus-blue-team]
---

# Cerverus Orchestrator

This skill chains the three Cerverus agents (Builder → Red Team → Blue Team) into a complete DevSecOps evaluation loop.

## When to Use
- Use when the user says "run Cerverus", "start the security scan", "execute the DevSecOps loop", or similar.
- Use when the user wants to analyze AND fix vulnerabilities in a single workflow.

## Prerequisites
- The target source code file must exist (default: `workspace/app.py` in the Cerverus project)
- The ontology file should exist at `config/ontology.json`

## Workflow Steps

### Step 1: Builder Analysis
1. Read the target file (`workspace/app.py`)
2. Activate the `cerverus-builder` skill mentally — analyze the code structure
3. Produce the structural analysis report
4. Save the analysis for the next step

### Step 2: Red Team Audit
1. Using the Builder's analysis AND the source code
2. Activate the `cerverus-red-team` skill mentally — perform the security audit
3. Identify all vulnerabilities with VULN-XXX IDs
4. If CLEAN SCAN is reported, skip to Step 4

### Step 3: Blue Team Patching
1. Using the Red Team's report AND the source code
2. Activate the `cerverus-blue-team` skill mentally — write patches
3. Output the complete patched file
4. Output the ontology update rules as JSON
5. Save the patched code to `workspace/app.py` (overwrite the original)
6. Append new rules to `config/ontology.json`

### Step 4: Report
1. Save the full audit report to `config/last_audit_report.json` with:
   - Timestamp
   - Builder analysis summary
   - Red Team findings
   - Blue Team patches
   - Ontology updates
2. Report the final status to the user

## Cyclical Mode
If the user requests "cyclical mode" or "keep scanning until clean":
1. After Step 3, re-read the patched `workspace/app.py`
2. Go back to Step 1 with the patched code
3. Repeat until the Red Team reports CLEAN SCAN or 5 cycles are reached
4. Create versioned backups before each patch (`app.py.v0`, `app.py.v1`, etc.)

## Guardrails
- Always back up the original file before patching
- Maximum 5 cycles in cyclical mode to prevent runaway execution
- Do NOT include API keys or secrets in any output or saved files
- Save all results to the `config/` directory
