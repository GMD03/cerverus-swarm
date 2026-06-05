# Project Cerverus: Autonomous Multi-Agent DevSecOps Swarm 🛡️🤖

![Project Status](https://img.shields.io/badge/Status-Active_Development-brightgreen)
![Version](https://img.shields.io/badge/Version-1.0--alpha-blue)
![Architecture](https://img.shields.io/badge/Architecture-Neuro--Symbolic_AI-orange)

## 📌 Overview
Project Cerverus is an advanced Autonomous Multi-Agent DevOps Swarm utilizing the OWL (Optimized Workforce Learning) framework and a DevSecOps Red Team / Blue Team evaluation loop. 

Originally conceptualized as Axiom, this project operates on a **Neuro-Symbolic AI pattern**. It moves beyond linear code-generation pipelines into a cyclical, self-improving enterprise system that dynamically updates a semantic knowledge graph to fundamentally improve its security protocols over time.

## 🏗️ The Agentic Evaluation Loop
Cerverus utilizes three specialized AI agents working in a continuous cycle:
* **The Builder Agent:** Modifies and generates codebase files based on system requirements.
* **The Red Team Agent (Attacker/Evaluator):** Audits the Builder's output for structural and security vulnerabilities (e.g., SQL injections, hardcoded credentials).
* **The Blue Team Agent (Defender/Reviewer):** Patches identified vulnerabilities and permanently updates the system's external memory—the OWL Ontology framework.

## ⚙️ Tech Stack & Model Selection
Balancing the "AI Trilemma" (privacy, capability, and cost-effectiveness) was central to the architecture. 
* **LLM Engine:** NVIDIA Nemotron 3 Super Free (120B/12B MoE)
* **Routing:** OpenRouter API
* **Framework:** Hermes Agent / camel-ai
* **Infrastructure:** Docker, Python 3.11, Flask (Dummy App)
* **Data Structure:** OWL Ontology Database

