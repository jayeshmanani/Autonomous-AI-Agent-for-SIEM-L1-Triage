from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.services.ai_service import analyze_event

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
SEED_FILE = DATA_DIR / "initial_triage_cases.json"
DB_FILE = DATA_DIR / "triage_cases.json"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def reset_database() -> None:
    """Restore working triage database from seed file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SEED_FILE.exists():
        shutil.copy(SEED_FILE, DB_FILE)


def _load_db() -> list[dict[str, Any]]:
    if not DB_FILE.exists():
        reset_database()
    if not DB_FILE.exists():
        return []
    with DB_FILE.open("r", encoding="utf-8") as file:
        payload = json.load(file)
    if isinstance(payload, list):
        return payload
    return []


def _save_db(cases: list[dict[str, Any]]) -> None:
    with DB_FILE.open("w", encoding="utf-8") as file:
        json.dump(cases, file, indent=2)


def get_all_cases() -> list[dict[str, Any]]:
    return _load_db()


def get_case_by_event_id(event_id: str) -> dict[str, Any] | None:
    for case in _load_db():
        if str(case.get("event_id")) == str(event_id):
            return case
    return None


def get_case_summary() -> dict[str, Any]:
    cases = _load_db()
    total = len(cases)
    escalated = sum(1 for item in cases if bool(item.get("escalated")))

    by_status: dict[str, int] = {}
    by_classification: dict[str, int] = {}

    for item in cases:
        status = str(item.get("status", "new")).lower()
        by_status[status] = by_status.get(status, 0) + 1

        classification = str(item.get("classification", "unknown")).lower()
        by_classification[classification] = by_classification.get(classification, 0) + 1

    return {
        "total_cases": total,
        "escalated_cases": escalated,
        "status_distribution": by_status,
        "classification_distribution": by_classification,
    }


def classify_and_tag_case(event_id: str) -> dict[str, Any] | None:
    cases = _load_db()
    target: dict[str, Any] | None = None

    for case in cases:
        if str(case.get("event_id")) == str(event_id):
            target = case
            break

    if target is None:
        return None

    analysis = analyze_event(target, abuse_score=int(target.get("abuse_score", 0) or 0))
    target["classification"] = analysis["classification"]
    target["priority"] = analysis["priority"]
    target["risk_score"] = analysis["risk_score"]
    target["tags"] = analysis["tags"]
    target["escalated"] = analysis["escalation"]["required"]
    target["escalation_target"] = analysis["escalation"]["target_queue"]
    target["updated_at"] = _now_iso()

    if target.get("status") in {None, "new"}:
        target["status"] = "triaged"

    _save_db(cases)
    return target


def escalate_case(event_id: str, reason: str = "Assistant escalation") -> dict[str, Any] | None:
    cases = _load_db()
    for case in cases:
        if str(case.get("event_id")) == str(event_id):
            case["escalated"] = True
            case["escalation_target"] = case.get("escalation_target") or "L2-IR"
            case["status"] = "escalated"
            case["escalation_reason"] = reason
            case["updated_at"] = _now_iso()
            _save_db(cases)
            return case
    return None


def search_cases(keyword: str, limit: int = 10) -> list[dict[str, Any]]:
    q = keyword.strip().lower()
    if not q:
        return []

    matches: list[dict[str, Any]] = []
    for case in _load_db():
        blob = " ".join(
            [
                str(case.get("event_id") or ""),
                str(case.get("event_type") or ""),
                str(case.get("severity") or ""),
                str(case.get("description") or ""),
                str(case.get("raw_log") or ""),
                " ".join(str(x) for x in case.get("tags", [])),
            ]
        ).lower()
        if q in blob:
            matches.append(case)
        if len(matches) >= limit:
            break
    return matches
