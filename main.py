"""
main.py — Cerverus Swarm: Agent Orchestration
===============================================
Entrypoint for the DevSecOps evaluation loop.

Modes:
  --mode single    (default) One Builder → Red Team → Blue Team pass using camel-ai
  --mode cyclical  Auto-patch and re-scan up to MAX_CYCLES iterations using camel-ai
  --mode hermes    Delegates orchestration to the Hermes Desktop API Gateway
"""

import argparse
from camel_orchestrator import run_single_pass, run_cyclical
from hermes_orchestrator import run_hermes

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cerverus Swarm — DevSecOps Agent Orchestration")
    parser.add_argument(
        "--mode",
        choices=["single", "cyclical", "hermes"],
        default="single",
        help="Execution mode: 'single' (one pass), 'cyclical' (auto-patch loop), 'hermes' (via Hermes Desktop)"
    )
    args = parser.parse_args()

    if args.mode == "hermes":
        run_hermes()
    elif args.mode == "cyclical":
        run_cyclical()
    else:
        run_single_pass()
