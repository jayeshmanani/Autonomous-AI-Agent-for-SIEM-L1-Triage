"""Hybrid AI logic for triage classification and chatbot analytics."""

from __future__ import annotations

import os
import re
from collections import Counter
from typing import Any

from dotenv import load_dotenv

load_dotenv()

SEVERITY_WEIGHT = {
    "info": 5,
    "low": 15,
    "medium": 35,
    "high": 60,
    "critical": 80,
    "emergency": 95,
}

MALICIOUS_KEYWORDS = (
    "ransomware",
    "zero-day",
    "exploit",
    "credential stuffing",
    "beaconing",
    "lateral movement",
    "c2",
    "malware",
    "brute force",
    "exfiltration",
    "phishing",
)

SUSPICIOUS_KEYWORDS = (
    "failed login",
    "anomaly",
    "unusual",
    "scan",
    "suspicious",
    "dns tunneling",
)

DECISION_FIELDS = (
    "event_type",
    "source",
    "severity",
    "description",
    "raw_log",
    "additional_info",
    "alert_type",
    "src_ip",
    "dst_ip",
    "advanced_metadata",
    "behavioral_analytics",
    "mitre_techniques",
)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_severity(value: str | None) -> str:
    sev = str(value or "medium").strip().lower()
    return sev if sev in SEVERITY_WEIGHT else "medium"


def _extract_keyword_hits(text_blob: str) -> tuple[list[str], list[str]]:
    malicious_hits = [item for item in MALICIOUS_KEYWORDS if item in text_blob]
    suspicious_hits = [item for item in SUSPICIOUS_KEYWORDS if item in text_blob]
    return malicious_hits, suspicious_hits


def _collect_fields_used(event: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    for field in DECISION_FIELDS:
        value = event.get(field)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        fields.append(field)
    return fields


def _build_triage_reasoning(
    event: dict[str, Any],
    risk_score: float,
    classification: str,
    priority: str,
    abuse_score: int,
    vt_score: int,
) -> list[str]:
    reasons: list[str] = []
    severity = _normalize_severity(event.get("severity"))
    reasons.append(
        f"Classification is {classification} with priority {priority} based on composite risk {risk_score}/100."
    )
    reasons.append(f"Severity input considered: {severity}.")

    metadata = event.get("advanced_metadata") or {}
    metadata_risk = _safe_float(metadata.get("risk_score"), 0.0)
    metadata_conf = _safe_float(metadata.get("confidence"), 0.5)
    reasons.append(
        f"Metadata contribution considered (risk_score={metadata_risk}, confidence={round(metadata_conf, 2)})."
    )

    behavior = event.get("behavioral_analytics") or {}
    behavior_flags: list[str] = []
    if bool(behavior.get("frequency_anomaly")):
        behavior_flags.append("frequency_anomaly")
    if bool(behavior.get("sequence_anomaly")):
        behavior_flags.append("sequence_anomaly")
    if _safe_float(behavior.get("baseline_deviation"), 0.0) > 0:
        behavior_flags.append("baseline_deviation")
    if behavior_flags:
        reasons.append(f"Behavior analytics flags influenced score: {', '.join(behavior_flags)}.")

    text_blob = " ".join(
        [
            str(event.get("raw_log") or ""),
            str(event.get("description") or ""),
            str(event.get("additional_info") or ""),
            str(event.get("alert_type") or ""),
        ]
    ).lower()
    malicious_hits, suspicious_hits = _extract_keyword_hits(text_blob)
    keyword_hits = malicious_hits or suspicious_hits
    if keyword_hits:
        reasons.append(f"Keyword signals found in log context: {', '.join(sorted(set(keyword_hits)))}.")

    if abuse_score > 0:
        reasons.append(f"Threat-intel AbuseIPDB score considered: {abuse_score}.")
    if vt_score > 0:
        reasons.append(f"Threat-intel VirusTotal score considered: {vt_score}.")

    used_fields = _collect_fields_used(event)
    reasons.append(f"Decision used fields: {', '.join(used_fields)}.")
    return reasons


def _calculate_risk_score(event: dict[str, Any], abuse_score: int, vt_score: int) -> float:
    severity = _normalize_severity(event.get("severity"))
    base = float(SEVERITY_WEIGHT[severity])

    metadata = event.get("advanced_metadata") or {}
    risk_score = _safe_float(metadata.get("risk_score"), 0.0)
    confidence = _safe_float(metadata.get("confidence"), 0.5)
    confidence = max(0.0, min(1.0, confidence))

    text_blob = " ".join(
        [
            str(event.get("raw_log") or ""),
            str(event.get("description") or ""),
            str(event.get("additional_info") or ""),
            str(event.get("alert_type") or ""),
        ]
    ).lower()

    keyword_bonus = 0.0
    malicious_hits, suspicious_hits = _extract_keyword_hits(text_blob)
    if malicious_hits:
        keyword_bonus += 20.0
    elif suspicious_hits:
        keyword_bonus += 10.0

    behavior = event.get("behavioral_analytics") or {}
    if bool(behavior.get("frequency_anomaly")):
        keyword_bonus += 8.0
    if bool(behavior.get("sequence_anomaly")):
        keyword_bonus += 10.0
    keyword_bonus += min(10.0, _safe_float(behavior.get("baseline_deviation"), 0.0) * 2.0)

    weighted_risk = (0.35 * base) + (0.25 * risk_score) + (0.2 * abuse_score) + (0.2 * vt_score)
    blended = weighted_risk * (0.8 + (0.2 * confidence)) + keyword_bonus
    return max(0.0, min(100.0, blended))


def _classify(score: float) -> tuple[str, str, str]:
    if score >= 75:
        return "malicious", "high", "P1"
    if score >= 50:
        return "suspicious", "medium", "P2"
    if score >= 30:
        return "suspicious", "low", "P3"
    return "authorized", "low", "P4"


def _build_tags(event: dict[str, Any], classification: str, risk_score: float, abuse_score: int, vt_score: int) -> list[str]:
    tags: set[str] = {f"classification:{classification}", f"event_type:{str(event.get('event_type', 'unknown')).lower()}"}
    severity = _normalize_severity(event.get("severity"))
    tags.add(f"severity:{severity}")

    if risk_score >= 75:
        tags.add("risk:critical")
    elif risk_score >= 50:
        tags.add("risk:elevated")
    else:
        tags.add("risk:normal")

    if abuse_score >= 70:
        tags.add("threat-intel:bad-ip")
    if vt_score >= 50:
        tags.add("threat-intel:vt-malicious")

    text_blob = " ".join(
        [
            str(event.get("description") or ""),
            str(event.get("additional_info") or ""),
            str(event.get("raw_log") or ""),
        ]
    )
    for mitre_id in sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text_blob, flags=re.IGNORECASE))):
        tags.add(f"mitre:{mitre_id.upper()}")

    return sorted(tags)


def analyze_event(event: dict[str, Any], abuse_score: int = 0, vt_score: int = 0) -> dict[str, Any]:
    """Run autonomous L1 triage and escalation decisioning for one event."""
    risk_score = round(_calculate_risk_score(event, abuse_score, vt_score), 2)
    classification, confidence_band, priority = _classify(risk_score)
    tags = _build_tags(event, classification, risk_score, abuse_score, vt_score)
    used_fields = _collect_fields_used(event)
    triage_reasoning = _build_triage_reasoning(event, risk_score, classification, priority, abuse_score, vt_score)

    escalation_required = (
        classification == "malicious"
        or risk_score >= 80
        or _normalize_severity(event.get("severity")) in {"critical", "emergency"}
    )

    reasons: list[str] = []
    if classification == "malicious":
        reasons.append("Model classified event as malicious.")
    if abuse_score >= 70:
        reasons.append("External AbuseIPDB threat-intel score is high.")
    if vt_score >= 50:
        reasons.append("VirusTotal flagged indicators as highly suspicious/malicious.")
    if risk_score >= 80:
        reasons.append("Composite risk score crossed escalation threshold.")
    if _normalize_severity(event.get("severity")) in {"critical", "emergency"}:
        reasons.append("Original SIEM severity is critical/emergency.")

    summary = (
        f"{str(event.get('event_type', 'unknown')).upper()} event classified as {classification} "
        f"with risk score {risk_score}/100 and priority {priority}."
    )

    return {
        "classification": classification,
        "severity_band": confidence_band,
        "priority": priority,
        "risk_score": risk_score,
        "abuse_confidence_score": abuse_score,
        "summary": summary,
        "decision_reasoning": triage_reasoning,
        "decision_fields_used": used_fields,
        "tags": tags,
        "escalation": {
            "required": escalation_required,
            "target_queue": "L2-IR" if escalation_required else "L1-monitoring",
            "reasons": reasons or ["No escalation trigger matched."],
        },
    }


def summarize_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {
            "total_events": 0,
            "severity_distribution": {},
            "event_type_distribution": {},
            "top_sources": [],
            "average_metadata_risk": 0.0,
        }

    severity_counter = Counter(_normalize_severity(str(e.get("severity") or "medium")) for e in events)
    event_type_counter = Counter(str(e.get("event_type") or "unknown").lower() for e in events)
    source_counter = Counter(str(e.get("source") or "unknown") for e in events)

    risk_values = []
    for event in events:
        metadata = event.get("advanced_metadata") or {}
        risk_values.append(_safe_float(metadata.get("risk_score"), 0.0))
    average_risk = round(sum(risk_values) / max(1, len(risk_values)), 2)

    return {
        "total_events": len(events),
        "severity_distribution": dict(severity_counter),
        "event_type_distribution": dict(event_type_counter),
        "top_sources": source_counter.most_common(5),
        "average_metadata_risk": average_risk,
    }


def answer_question(question: str, events: list[dict[str, Any]], triage_history: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Chatbot-style responses for data exploration and triage status."""
    triage_history = triage_history or []
    q = question.strip().lower()

    if not q:
        return {"answer": "Ask a question about event counts, severities, event types, or escalations.", "evidence": []}

    summary = summarize_events(events)

    if "how many" in q and any(word in q for word in ("critical", "high", "medium", "low", "info", "emergency")):
        for severity in ("critical", "high", "medium", "low", "info", "emergency"):
            if severity in q:
                count = summary["severity_distribution"].get(severity, 0)
                return {
                    "answer": f"There are {count} events with severity '{severity}'.",
                    "evidence": [{"severity": severity, "count": count}],
                }

    if "event type" in q or "distribution" in q or "breakdown" in q:
        return {
            "answer": "Here is the event type distribution in the loaded dataset.",
            "evidence": summary["event_type_distribution"],
        }

    if "summary" in q or "overview" in q or "dataset" in q:
        return {
            "answer": "Here is a high-level summary of the loaded SIEM dataset.",
            "evidence": summary,
        }

    if "escalat" in q:
        escalated = [item for item in triage_history if item.get("analysis", {}).get("escalation", {}).get("required")]
        return {
            "answer": f"{len(escalated)} triaged events are currently marked for escalation.",
            "evidence": escalated[:5],
        }

    if "top source" in q or "source" in q:
        return {
            "answer": "Top data sources in the loaded dataset:",
            "evidence": summary["top_sources"],
        }

    keyword_matches = []
    for event in events:
        blob = " ".join(
            [
                str(event.get("description") or ""),
                str(event.get("raw_log") or ""),
                str(event.get("event_type") or ""),
            ]
        ).lower()
        if q in blob:
            keyword_matches.append(event)
        if len(keyword_matches) >= 5:
            break

    if keyword_matches:
        return {
            "answer": f"I found {len(keyword_matches)} sample events matching your query.",
            "evidence": keyword_matches,
        }

    return {
        "answer": (
            "I can help with event counts, severity breakdowns, source distribution, "
            "dataset overview, and escalation status."
        ),
        "evidence": [],
    }