from __future__ import annotations

import asyncio
import os
from typing import Any

from dotenv import load_dotenv
from pydantic_ai import Agent

from app.models.assistant import AssistantResponse
from app.services.database import (
    classify_and_tag_case,
    escalate_case,
    get_all_cases,
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


def _build_fallback_response(prompt: str) -> AssistantResponse:
    summary = get_case_summary()
    top_message = (
        f"I could not reach the configured LLM right now, but I can still help. "
        f"Current totals: {summary['total_cases']} cases, {summary['escalated_cases']} escalated. "
        f"You asked: {prompt}"
    )
    return AssistantResponse(
        message=top_message,
        top_threat_identified=None,
        escalation_actions_queued=None,
    )


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
    try:
        result = await asyncio.wait_for(
            siem_agent.run(prompt, message_history=message_history),
            timeout=ASSISTANT_TIMEOUT_SECONDS,
        )
        return result.output, result.all_messages()
    except Exception:
        fallback = _build_fallback_response(prompt)
        return fallback, message_history
