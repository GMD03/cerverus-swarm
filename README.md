# Cerverus Swarm

**Autonomous Multi-Agent DevSecOps System** — An AI-powered security swarm that analyzes your code, finds vulnerabilities, and patches them automatically.

Built on [Hermes Agent](https://hermes-agent.nousresearch.com/) by Nous Research · Powered by NVIDIA Nemotron 3 Super via [OpenRouter](https://openrouter.ai/)

---

## Architecture

Cerverus deploys three specialized AI agents in an automated security pipeline:

| Agent | Role | Output |
|-------|------|--------|
| **Builder** | Analyzes code structure, endpoints, and data flows | Structural analysis report |
| 🔴 **Red Team** | Attacks the code — finds OWASP Top 10 vulnerabilities | Vulnerability report (VULN-001, etc.) |
| 🔵 **Blue Team** | Patches every vulnerability and updates the knowledge base | Patched code + OWL Ontology rules |

### Security Pipeline
```
Your System → Hermes Agent → Docker Sandbox → Nemotron 3 Super (via OpenRouter)
```
- **Hermes Agent** strips secrets from all API payloads
- **Docker Sandbox** isolates execution in a non-root container
- **OWL Ontology** stores learned security rules permanently

---

## Quick Start

### Prerequisites
- [Docker Desktop](https://docs.docker.com/desktop/install/windows-install/) (with WSL 2)
- [Hermes Desktop](https://hermes-agent.nousresearch.com/desktop) (optional — for Hermes mode)
- An [OpenRouter API key](https://openrouter.ai/) (free tier works)

### Setup
```bash
git clone https://github.com/YourUsername/cerverus-swarm.git
cd cerverus-swarm
cp .env.example .env
# Edit .env with your OpenRouter API key
```

### Run
```bash
# Single-pass mode (one cycle)
docker-compose up --build

# Cyclical mode (auto-patch until clean, max 5 cycles)
docker-compose run cerverus-sandbox python main.py --mode cyclical

# View the dashboard
# Open http://localhost:8080

# View the landing page
# Open http://localhost:3000
```

---

## Tech Stack

| Technology | Purpose |
|-----------|---------|
| **Hermes Agent** (Nous Research) | AI agent orchestration platform |
| **NVIDIA Nemotron 3 Super** | 120B parameter MoE model (free via OpenRouter) |
| **camel-ai** | Multi-agent framework (standalone fallback) |
| **Docker** | Sandboxed execution environment |
| **Flask** | Dashboard web UI + target vulnerable app |
| **OWL Ontology** | Persistent knowledge base (JSON) |
| **Python 3.11** | Core language |

---

## Project Structure

```
cerverus-swarm/
├── main.py                # Agent orchestration (single/cyclical/hermes modes)
├── hermes_guardian.py      # Security gateway + sanitization engine
├── dashboard.py            # Web dashboard (port 8080)
├── hermes-skills/          # Hermes Agent skill definitions
│   ├── cerverus-builder/   #   Builder Agent skill
│   ├── cerverus-red-team/  #   Red Team Agent skill
│   ├── cerverus-blue-team/ #   Blue Team Agent skill
│   └── cerverus-orchestrator/ # Master orchestration skill
├── workspace/
│   └── app.py              # Target vulnerable Flask app
├── config/
│   ├── ontology.json       # OWL knowledge base
│   └── last_audit_report.json
├── landing/                # Recruiter-facing landing page (port 3000)
├── templates/              # Dashboard HTML templates
├── static/                 # Dashboard CSS
├── Dockerfile
├── docker-compose.yml
└── .env                    # API keys (gitignored)
```

---

## License

This project is an academic portfolio piece demonstrating enterprise-grade AI systems architecture.
