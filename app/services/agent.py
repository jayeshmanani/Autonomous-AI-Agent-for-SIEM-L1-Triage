from __future__ import annotations

import asyncio
from collections import Counter
import os
import re
from typing import Any

from dotenv import load_dotenv
from pydantic_ai import Agent

from app.models.assistant import AssistantResponse, EscalationAction
from app.services.database import (
    classify_and_tag_case,
    escalate_case,
    get_all_cases,
    get_change_audit,
    get_case_by_event_id,
    get_case_summary,
    search_cases,
)

load_dotenv()


def fetch_triage_data() -> list[dict[str, Any]]:
    """Get all triage cases from the JSON-backed database."""
    return get_all_cases()


def fetch_triage_summary() -> dict[str, Any]:
    """Get high-level triage metrics for analyst quick view."""
    return get_case_summary()


def lookup_case(event_id: str) -> dict[str, Any] | str:
    """Lookup a specific case by event_id."""
    case = get_case_by_event_id(event_id)
    return case if case else f"Case not found for event_id={event_id}"


def classify_and_tag(event_id: str) -> dict[str, Any] | str:
    """Run triage classification and tagging for one case."""
    case = classify_and_tag_case(event_id)
    return case if case else f"Case not found for event_id={event_id}"


def escalate(event_id: str, reason: str = "Manual analyst escalation") -> dict[str, Any] | str:
    """Escalate one case to L2 incident response queue."""
    case = escalate_case(event_id, reason=reason)
    return case if case else f"Case not found for event_id={event_id}"


def search(keyword: str) -> list[dict[str, Any]]:
    """Search cases by keyword across common fields and tags."""
    return search_cases(keyword, limit=10)


def _severity_rank(value: str | None) -> int:
    order = {
        "emergency": 6,
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    return order.get(str(value or "").lower(), 0)


def _top_priority_cases(cases: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    def _score(case: dict[str, Any]) -> tuple[int, int, float, int]:
        escalated = 1 if bool(case.get("escalated")) else 0
        severity = _severity_rank(str(case.get("severity") or ""))
        risk = float(case.get("risk_score") or 0.0)
        is_new = 1 if str(case.get("status") or "new").lower() in {"new", "triaged"} else 0
        return (escalated, severity, risk, is_new)

    ranked = sorted(cases, key=_score, reverse=True)
    return ranked[:limit]


def _build_priority_recommendations(cases: list[dict[str, Any]]) -> list[str]:
    escalated_new = [
        case
        for case in cases
        if bool(case.get("escalated")) and str(case.get("status") or "new").lower() in {"new", "triaged"}
    ]
    high_risk = [case for case in cases if float(case.get("risk_score") or 0.0) >= 80]
    high_severity = [case for case in cases if _severity_rank(case.get("severity")) >= 5]

    recommendations = [
        f"Triage escalated new/triaged cases first: {len(escalated_new)} open high-priority items.",
        f"Validate top risk events (risk_score >= 80): {len(high_risk)} cases.",
        f"Focus on critical/emergency severity stream: {len(high_severity)} cases.",
    ]
    return recommendations


def _local_assistant_response(prompt: str) -> AssistantResponse:
    cases = get_all_cases()
    summary = get_case_summary()
    q = prompt.strip().lower()

    escalated = int(summary.get("escalated_cases", 0))
    total = int(summary.get("total_cases", 0))

    top_cases = _top_priority_cases(cases, limit=5)
    top_case = top_cases[0] if top_cases else None
    top_threat = None
    if top_case is not None:
        top_threat = (
            f"{top_case.get('event_id')} "
            f"({top_case.get('event_type')}, severity={top_case.get('severity')}, risk={top_case.get('risk_score')})"
        )

    queued_actions = [
        EscalationAction(
            event_id=str(case.get("event_id")),
            action=f"Review and escalate to {case.get('escalation_target') or 'L2-IR'}",
        )
        for case in top_cases
        if bool(case.get("escalated"))
    ]

    if ("escalat" in q and "priorit" in q) or ("how many cases are escalated" in q):
        recommendations = _build_priority_recommendations(cases)
        coverage = f"{(escalated / total * 100):.1f}%" if total else "0.0%"
        message = (
            f"{escalated} out of {total} cases are escalated ({coverage}).\n"
            f"Priority right now:\n"
            f"1) {recommendations[0]}\n"
            f"2) {recommendations[1]}\n"
            f"3) {recommendations[2]}"
        )
        return AssistantResponse(
            message=message,
            top_threat_identified=top_threat,
            escalation_actions_queued=queued_actions or None,
        )

    if "summary" in q or "overview" in q:
        status_distribution = summary.get("status_distribution", {})
        class_distribution = summary.get("classification_distribution", {})
        message = (
            f"Current case overview: total={total}, escalated={escalated}. "
            f"Status split={status_distribution}. Classification split={class_distribution}."
        )
        return AssistantResponse(
            message=message,
            top_threat_identified=top_threat,
            escalation_actions_queued=queued_actions or None,
        )

    if "source" in q or "origin" in q or "event type" in q:
        event_counts = Counter(str(case.get("event_type") or "unknown").lower() for case in cases)
        top_event_types = event_counts.most_common(3)
        message = f"Top origins/event types by volume: {top_event_types}."
        return AssistantResponse(
            message=message,
            top_threat_identified=top_threat,
            escalation_actions_queued=queued_actions or None,
        )

    return AssistantResponse(
        message=(
            "LLM is temporarily unavailable, so I switched to local triage intelligence. "
            f"We currently have {total} cases and {escalated} escalated. "
            "You can ask for escalation priorities, dataset summary, or origin-based trends."
        ),
        top_threat_identified=top_threat,
        escalation_actions_queued=queued_actions or None,
    )


UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


def _extract_event_id(prompt: str) -> str | None:
    match = UUID_PATTERN.search(prompt)
    if not match:
        return None
    return match.group(0)


def _handle_deterministic_action(prompt: str) -> AssistantResponse | None:
    """Handle write-actions deterministically so updates work even when LLM is unavailable."""
    q = prompt.strip().lower()

    if "audit" in q or "verify" in q or "reflect" in q or "updated" in q:
        audit = get_change_audit(limit=5)
        return AssistantResponse(
            message=(
                f"Audit summary: changed_records={audit['changed_records']}, "
                f"classified_non_unknown={audit['classified_non_unknown']}, "
                f"status_not_new={audit['status_not_new']}, updated_at_count={audit['updated_at_count']}."
            ),
            top_threat_identified=None,
            escalation_actions_queued=None,
        )

    event_id = _extract_event_id(prompt)
    if not event_id:
        return None

    if "classify" in q or "tag" in q or "triage" in q:
        case = classify_and_tag_case(event_id)
        if case is None:
            return AssistantResponse(
                message=f"No case found for event_id={event_id}.",
                top_threat_identified=None,
                escalation_actions_queued=None,
            )

        queued = (
            [
                EscalationAction(
                    event_id=event_id,
                    action=f"Escalate to {case.get('escalation_target') or 'L2-IR'}",
                )
            ]
            if bool(case.get("escalated"))
            else None
        )
        return AssistantResponse(
            message=(
                f"Case {event_id} updated: classification={case.get('classification')}, "
                f"priority={case.get('priority')}, risk_score={case.get('risk_score')}, "
                f"status={case.get('status')}."
            ),
            top_threat_identified=event_id,
            escalation_actions_queued=queued,
        )

    if "escalate" in q:
        case = escalate_case(event_id, reason="Assistant requested escalation")
        if case is None:
            return AssistantResponse(
                message=f"No case found for event_id={event_id}.",
                top_threat_identified=None,
                escalation_actions_queued=None,
            )

        return AssistantResponse(
            message=(
                f"Case {event_id} escalated successfully to "
                f"{case.get('escalation_target') or 'L2-IR'}."
            ),
            top_threat_identified=event_id,
            escalation_actions_queued=[
                EscalationAction(
                    event_id=event_id,
                    action=f"Escalated to {case.get('escalation_target') or 'L2-IR'}",
                )
            ],
        )

    return None


def _build_fallback_response(prompt: str) -> AssistantResponse:
    return _local_assistant_response(prompt)


MODEL_NAME = os.getenv("PydanticAI_MODEL", "vertexai:gemini-2.5-flash")
ASSISTANT_TIMEOUT_SECONDS = float(os.getenv("ASSISTANT_TIMEOUT_SECONDS", "25"))

siem_agent = Agent(
    MODEL_NAME,
    output_type=AssistantResponse,
    tools=[
        fetch_triage_data,
        fetch_triage_summary,
        lookup_case,
        classify_and_tag,
        escalate,
        search,
    ],
    system_prompt=(
        "You are an autonomous SOC L1 triage assistant. "
        "You help analysts classify alerts, tag events, and escalate to L2 when justified. "
        "Rules: "
        "1) Use fetch_triage_summary or fetch_triage_data before broad claims. "
        "2) For event-level tasks use lookup_case then classify_and_tag if needed. "
        "3) Escalate when severity is critical/emergency, classification is malicious, or risk_score >= 80. "
        "4) Explain reasoning clearly and keep analyst responses concise and actionable."
    ),
)


async def run_siem_assistant(prompt: str, message_history: list[Any]) -> tuple[AssistantResponse, list[Any]]:
    """Run the SIEM assistant and return structured response plus updated history."""
    deterministic = _handle_deterministic_action(prompt)
    if deterministic is not None:
        return deterministic, message_history

    try:
        result = await asyncio.wait_for(
            siem_agent.run(prompt, message_history=message_history),
            timeout=ASSISTANT_TIMEOUT_SECONDS,
        )
        return result.output, result.all_messages()
    except Exception:
        fallback = _build_fallback_response(prompt)
        return fallback, message_history
