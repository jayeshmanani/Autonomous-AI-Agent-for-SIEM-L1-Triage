# Autonomous-AI-Agent-for-SIEM-L1-Triage
Autonomous AI agent for SIEM L1 triage. Analyzes and prioritizes alerts, enriches them with context, and performs initial investigation steps to speed up response and reduce analyst workload, enabling teams to focus on advanced threat analysis.


# About the Dataset used for AI Agent
# Advanced SIEM Dataset (https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset)

## Dataset Description

The advanced_siem_dataset is a synthetic dataset of 100,000 security event records designed for training machine learning (ML) and artificial intelligence (AI) models in cybersecurity.

It simulates logs from Security Information and Event Management (SIEM) systems, capturing diverse event types such as firewall activities, intrusion detection system (IDS) alerts, authentication attempts, endpoint activities, network traffic, cloud operations, IoT device events, and AI system interactions.

The dataset includes advanced metadata, MITRE ATT&CK techniques, threat actor associations, and unconventional indicators of compromise (IOCs), making it suitable for tasks like anomaly detection, threat classification, predictive analytics, and user and entity behavior analytics (UEBA).

## Dataset Structure

The dataset is stored in a single train split in JSON Lines format, with each record representing a security event. Below is the schema:
```
Field
Type
Description

event_id
String
Unique identifier (UUID) for the event.

timestamp
String
ISO 8601 timestamp of the event.

event_type
String
Event category: firewall, ids_alert, auth, endpoint, network, cloud, iot, ai.

source
String
Security tool and version (e.g., "Splunk v9.0.2").

severity
String
Severity level: info, low, medium, high, critical, emergency.

description
String
Human-readable summary of the event.

raw_log
String
CEF-formatted raw log with optional noise.

advanced_metadata
Dict
Metadata including geo_location, device_hash, user_agent, session_id, risk_score, confidence.

behavioral_analytics
Dict
Optional; includes baseline_deviation, entropy, frequency_anomaly, sequence_anomaly (10% of records).

Event-specific fields
Varies
E.g., src_ip, dst_ip, alert_type (for ids_alert), user (for auth), action, etc.
```

## Sample Record:
```
{
  "event_id": "123e4567-e89b-12d3-a456-426614174000",
  "timestamp": "2025-07-11T11:27:00+00:00",
  "event_type": "ids_alert",
  "source": "Snort v2.9.20",
  "severity": "high",
  "description": "Snort Alert: Zero-Day Exploit detected from 192.168.1.100 targeting N/A | MITRE Technique: T1059.001",
  "raw_log": "CEF:0|Snort v2.9.20|SIEM|1.0|100|ids_alert|high| desc=Snort Alert: Zero-Day Exploit detected from 192.168.1.100 targeting N/A | MITRE Technique: T1059.001",
  "advanced_metadata": {
    "geo_location": "United States",
    "device_hash": "a1b2c3d4e5f6",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
    "session_id": "987fcdeb-1234-5678-abcd-426614174000",
    "risk_score": 85.5,
    "confidence": 0.95
  },
  "alert_type": "Zero-Day Exploit",
  "signature_id": "SIG-1234",
  "category": "Exploit",
  "additional_info": "MITRE Technique: T1059.001"
}
```

## Intended Use

This dataset is intended for:
Anomaly Detection: Identify unusual patterns (e.g., zero-day exploits, beaconing) using unsupervised learning.
Threat Classification: Classify events by severity or event_type for incident prioritization.
User and Entity Behavior Analytics (UEBA): Detect insider threats or compromised credentials by analyzing auth or endpoint events.
Predictive Analytics: Forecast high-risk periods using time-series analysis of risk_score and timestamp.
Threat Hunting: Leverage MITRE ATT&CK techniques and IOCs in additional_info for threat intelligence.
Red Teaming: Simulate adversarial scenarios (e.g., APTs, DNS tunneling) for testing SIEM systems.

## Limitations:
Synthetic Nature: The dataset is synthetic and may not fully capture real-world SIEM log complexities, such as vendor-specific formats or noise patterns.
Class Imbalance: Certain event_type (e.g., ai, iot) or severity (e.g., emergency) values may be underrepresented. Use data augmentation or reweighting for balanced training.
Missing Values: Some dst_ip fields in ids_alert events are "N/A", requiring imputation or filtering.
Timestamp Anomalies: 5% of records include intentional timestamp anomalies (future/past dates) to simulate time-based attacks, which may require special handling.

## Working Autonomous L1 Triage Agent

This repository now includes a working FastAPI-based L1 triage agent with:

- Log/event classification (`authorized`, `suspicious`, `malicious`)
- Risk scoring with SIEM severity + metadata + optional AbuseIPDB enrichment
- Automatic escalation recommendation to `L2-IR` when thresholds are met
- Event tagging (classification, severity, event type, MITRE techniques)
- Chatbot endpoint to ask questions about the loaded dataset and triage history

## Project Structure

```
app/
  main.py                  # FastAPI API endpoints
  services/
    ai_service.py          # Triage scoring, classification, tags, chatbot logic
    threat_intel.py        # AbuseIPDB IP reputation lookup
  utils/
    log_parser.py          # CEF parsing, IP extraction, dataset loading
data/
  sample_logs.json
```

## Environment Variables

Configure in `.env`:

- `ABUSEIPDB_API_KEY` (optional but recommended for external IP reputation)
- `SIEM_DATASET_PATH` (optional, defaults to `data/sample_logs.json`)
- `MAX_DATASET_RECORDS` (optional, defaults to `25000`)
- `MAX_BATCH_SIZE` (optional, defaults to `200`)

## Run the API

```bash
uv sync
uv run uvicorn app.main:app --reload
```

Open docs at:

- `http://127.0.0.1:8000/docs`

## Endpoints

- `GET /health`
  - Returns service status, loaded dataset size, and triage history size.

- `POST /triage`
  - Triage one event or raw log.
  - Body:

```json
{
  "event": {
    "event_type": "ids_alert",
    "severity": "high",
    "description": "Credential stuffing detected from 54.159.34.148",
    "raw_log": "CEF:0|Snort|SIEM|1.0|100|ids_alert|high| desc=Credential Stuffing detected from 54.159.34.148",
    "src_ip": "54.159.34.148",
    "advanced_metadata": {"risk_score": 72.5, "confidence": 0.91}
  },
  "enrich_threat_intel": true
}
```

- `POST /triage/batch`
  - Triage multiple events in one request.

- `POST /tag`
  - Returns tags, classification, and priority for an event.

- `GET /analysis/summary`
  - Returns dataset-level analytics (severity breakdown, event type distribution, top sources).

- `POST /chat`
  - Ask questions like:
    - "Give dataset summary"
    - "How many critical events?"
    - "Show event type distribution"
    - "How many escalations do we have?"

## Notes

- The loader is resilient to large and non-strict JSON dataset formatting.
- Threat-intel lookup is cached to reduce repeated API calls for the same IP.
- If no AbuseIPDB key is set, triage still works using internal scoring rules.

