"""FastAPI entrypoint for autonomous SIEM L1 triage agent."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .routers.assistant import router as assistant_router
from .services.ai_service import analyze_event, answer_question, summarize_events
from .services.threat_intel import get_ip_reputation
from .utils.log_parser import load_events, normalize_event

app = FastAPI(title="Autonomous AI Agent for SIEM L1 Triage", version="1.0.0")
app.include_router(assistant_router)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET = PROJECT_ROOT / "data" / "sample_logs.json"
STATIC_DIR = Path(__file__).resolve().parent / "static"

MAX_DATASET_RECORDS = int(os.getenv("MAX_DATASET_RECORDS", "25000"))
MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "200"))

TRIAGE_HISTORY: list[dict[str, Any]] = []

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class TriageRequest(BaseModel):
    raw_log: str | None = None
    event: dict[str, Any] | None = None
    enrich_threat_intel: bool = True


class BatchTriageRequest(BaseModel):
    events: list[dict[str, Any] | str] = Field(default_factory=list)
    enrich_threat_intel: bool = True


class ChatRequest(BaseModel):
    question: str


class TagRequest(BaseModel):
    raw_log: str | None = None
    event: dict[str, Any] | None = None
    abuse_score: int = 0


@lru_cache(maxsize=1)
def get_dataset() -> list[dict[str, Any]]:
    dataset_path = Path(os.getenv("SIEM_DATASET_PATH", str(DEFAULT_DATASET)))
    return load_events(dataset_path, max_records=MAX_DATASET_RECORDS)


def _triage_single(payload: dict[str, Any] | str, enrich_threat_intel: bool = True) -> dict[str, Any]:
    event = normalize_event(payload)
    src_ip = event.get("src_ip")
    abuse_score = get_ip_reputation(src_ip) if enrich_threat_intel else 0
    analysis = analyze_event(event, abuse_score=abuse_score)

    result = {
        "event_id": event.get("event_id"),
        "event": event,
        "extracted_ip": src_ip,
        "analysis": analysis,
    }
    TRIAGE_HISTORY.append(result)
    if len(TRIAGE_HISTORY) > 5000:
        del TRIAGE_HISTORY[:1000]
    return result


@app.get("/health")
async def health() -> dict[str, Any]:
    events = get_dataset()
    return {
        "status": "ok",
        "dataset_loaded": len(events),
        "max_dataset_records": MAX_DATASET_RECORDS,
        "triage_history_size": len(TRIAGE_HISTORY),
    }


@app.get("/")
async def home() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="UI file not found.")
    return FileResponse(index_file)


@app.post("/triage")
async def triage_log(item: TriageRequest) -> dict[str, Any]:
    payload = item.event if item.event is not None else item.raw_log
    if payload is None:
        raise HTTPException(status_code=400, detail="Provide either 'raw_log' or 'event'.")
    return _triage_single(payload, enrich_threat_intel=item.enrich_threat_intel)


@app.post("/triage/batch")
async def triage_batch(request: BatchTriageRequest) -> dict[str, Any]:
    if not request.events:
        raise HTTPException(status_code=400, detail="'events' must contain at least one item.")
    if len(request.events) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Batch too large. Max allowed is {MAX_BATCH_SIZE}.",
        )

    results = [_triage_single(item, enrich_threat_intel=request.enrich_threat_intel) for item in request.events]
    escalated = sum(1 for item in results if item.get("analysis", {}).get("escalation", {}).get("required"))
    return {
        "processed": len(results),
        "escalated": escalated,
        "results": results,
    }


@app.post("/triage/by-origin/{origin}")
async def triage_by_origin(origin: str, limit: int = 100, enrich_threat_intel: bool = False) -> dict[str, Any]:
    normalized_origin = origin.strip().lower()
    if not normalized_origin:
        raise HTTPException(status_code=400, detail="Origin cannot be empty.")

    safe_limit = max(1, min(limit, MAX_BATCH_SIZE))
    events = get_dataset()

    matched = [
        event
        for event in events
        if (
            normalized_origin in str(event.get("event_type", "")).lower()
            or normalized_origin in str(event.get("source", "")).lower()
            or normalized_origin in str(event.get("src_ip", "")).lower()
            or normalized_origin in str(event.get("dst_ip", "")).lower()
            or normalized_origin in str(event.get("geo_location", "")).lower()
        )
    ]

    if not matched:
        return {
            "origin": origin,
            "matched": 0,
            "processed": 0,
            "escalated": 0,
            "results": [],
        }

    selected = matched[:safe_limit]
    results = [_triage_single(event, enrich_threat_intel=enrich_threat_intel) for event in selected]
    escalated = sum(1 for item in results if item.get("analysis", {}).get("escalation", {}).get("required"))

    return {
        "origin": origin,
        "matched": len(matched),
        "processed": len(results),
        "escalated": escalated,
        "results": results,
    }


@app.post("/tag")
async def tag_event(request: TagRequest) -> dict[str, Any]:
    payload = request.event if request.event is not None else request.raw_log
    if payload is None:
        raise HTTPException(status_code=400, detail="Provide either 'raw_log' or 'event'.")

    event = normalize_event(payload)
    analysis = analyze_event(event, abuse_score=max(0, min(100, request.abuse_score)))
    return {
        "event": event,
        "tags": analysis["tags"],
        "classification": analysis["classification"],
        "priority": analysis["priority"],
    }


@app.get("/analysis/summary")
async def analysis_summary() -> dict[str, Any]:
    events = get_dataset()
    summary = summarize_events(events)
    summary["triage_history_size"] = len(TRIAGE_HISTORY)
    summary["escalated_in_history"] = sum(
        1
        for item in TRIAGE_HISTORY
        if item.get("analysis", {}).get("escalation", {}).get("required")
    )
    return summary


@app.post("/chat")
async def chat(request: ChatRequest) -> dict[str, Any]:
    events = get_dataset()
    answer = answer_question(request.question, events, triage_history=TRIAGE_HISTORY)
    return {
        "question": request.question,
        "response": answer,
    }