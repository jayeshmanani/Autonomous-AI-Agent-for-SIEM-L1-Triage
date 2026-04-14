from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel
from pydantic_ai.messages import ModelMessage

from app.services.agent import run_siem_assistant
from app.services.database import get_change_audit

router = APIRouter(prefix="/assistant", tags=["assistant"])

# In-memory session store for demo use. Replace with Redis/Postgres in production.
chat_sessions: dict[str, list[ModelMessage]] = {}


class UserQuery(BaseModel):
    session_id: str
    prompt: str


@router.get("/welcome/{session_id}")
async def welcome_message(session_id: str) -> dict[str, str]:
    chat_sessions[session_id] = []
    return {
        "session_id": session_id,
        "message": (
            "Welcome to the SIEM L1 Triage Assistant. "
            "I can classify alerts, tag cases, summarize risk trends, and escalate to L2-IR when needed. "
            "What should we investigate first?"
        ),
    }


@router.post("/ask")
async def ask_assistant(query: UserQuery):
    history = chat_sessions.get(query.session_id, [])
    output, updated_history = await run_siem_assistant(query.prompt, history)
    chat_sessions[query.session_id] = updated_history
    return output.model_dump()


@router.get("/audit")
async def audit_changes(limit: int = 10):
    safe_limit = max(1, min(limit, 1000))
    return get_change_audit(limit=safe_limit)
