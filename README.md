---
title: Autonomous SIEM L1 Triage
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
---

# Autonomous AI Agent for SIEM L1 Triage 🛡️

**Live Demo**: [https://autonomous-ai-agent-for-siem-l1-triage.onrender.com](https://autonomous-ai-agent-for-siem-l1-triage.onrender.com)

**Welcome to the future of Security Operations.** 
The SIEM L1 Triage Agent is an autonomous, context-aware AI assistant designed to systematically eliminate alert fatigue. By natively integrating with your JSON-backed case database and external Threat Intelligence platforms (VirusTotal, AbuseIPDB), this agent autonomously investigates, scores, tags, and escalates security events - acting as a true L1 companion for your SOC analysts.

---

## 🌟 Key Product Features

- **Automated Alert Triage**: The agent autonomously parses unstructured logs, calculates deterministic risk scores (0-100), and classifies events (`malicious`, `suspicious`, `authorized`).
- **Dynamic Threat Intelligence (New!)**: Natively connects to external APIs. Automatically extracts URLs, IPs, and file hashes from logs and cross-references them against **VirusTotal** and **AbuseIPDB** to dynamically inflate risk scoring on positive hits.
- **Conversational Chatbot Interface**: Built on FastAPI, the web interface allows SOC analysts to interface conversationally with the underlying data. Ask queries like: *"Show me all critical escalated cases"* or *"Can you scan this IP via VirusTotal?"*
- **Bulk Origin Filtering & Triage**: Safely segregate SIEM logic! Analysts can filter a massive database by `origin` strings or command the agent to bulk-triage missing events in parallel.
- **Data-Driven Evaluation Pipeline**: Fully instrumented with **Langfuse**. Generate real-world evaluations systematically to perfectly monitor your AI's reasoning accuracy across different edge cases.

---

## 🛠️ Architecture & Tech Stack

- **Core AI Engine**: Google Vertex AI / Gemini (`pydantic-ai`)
- **Backend API**: FastAPI / Python 3.13 
- **Database**: Local high-speed JSON datastore with thread-safe atomic locking (`filelock`)
- **Telemetry & Evals**: Langfuse SDK v3

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.13 installed alongside `uv` (our lightning-quick package manager).

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Environment Variables (`.env`)
You must configure your API keys locally before running the agent. Create a `.env` file in the root of the project:

```env
# AI Model Configuration
GEMINI_API_KEY=your_gemini_api_key_here
PydanticAI_MODEL=vertexai:gemini-2.5-flash
ASSISTANT_TIMEOUT_SECONDS=25

# Threat Intelligence Context APIs
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Langfuse Evaluation & Telemetry
LANGFUSE_SECRET_KEY=sk-lf-...
LANGFUSE_PUBLIC_KEY=pk-lf-...
LANGFUSE_HOST=https://cloud.langfuse.com
```

### 3. Installation
Using `uv`, you can instantly sync the project dependencies without worrying about stale virtual environments.

```bash
# Sync dependencies
uv sync
```

### 4. Running the Local API & Interface
To spin up the local FastAPI web server, execute:

```bash
# Recommended: Run via Python directly to enable network accessibility (0.0.0.0 binding)
uv run python -m app.main

# Alternative: Hot-reload for local development
uv run uvicorn app.main:app --reload
```
Once running, you can connect your frontend interface or test the raw endpoints by navigating to `http://localhost:8000/docs` in your browser and the SIEM L1 Agent Chat UI at `http://localhost:8000`. By default, the application is configured to bind to `0.0.0.0` making it suitable for direct container/cloud exposure out-of-the-box!

### 5. Running the AI Evaluation Pipeline
Want to test how well the LLM classifies threats without executing false positives in production? Run the automated evaluation suite!

```bash
uv run python -m scripts.run_evaluation_pipeline
```

---

## 🧠 Chatbot Interaction Examples

Connect to the `/assistant/ask` endpoint and prompt the agent naturally!

> **Analyst**: *"What are my top priorities right now?"*  
> **Agent**: *"You have 4 new and unclassified cases. Your top priority should be to triage these new alerts to determine their classification and severity.
Reasoning: 4 cases are currently in "new" status and All 4 cases have an "unknown" classification."*

> **Analyst**: *"Can you scan 206.168.34.44?"*  
> **Agent**: *"The IP address 206.168.34.44 has a highly malicious reputation score of 100. This indicates a high likelihood of malicious activity.
Reasoning: AbuseIPDB confidence score for 206.168.34.44 is 100, indicating confirmed malicious activity."*

> **Analyst**: *"206.168.34.44 scan in virustotal"*  
> **Agent**: *"VirusTotal scan for 206.168.34.44 shows a malicious score of 11. This indicates some reported malicious activity by various security vendors.
Reasoning: VirusTotal aggregated malicious score for 206.168.34.44 is 11."*



