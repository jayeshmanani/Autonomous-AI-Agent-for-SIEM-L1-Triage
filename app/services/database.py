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


def get_change_audit(limit: int = 10) -> dict[str, Any]:
    """Compare working DB against seed DB and report changed records."""
    current_cases = _load_db()

    if SEED_FILE.exists():
        with SEED_FILE.open("r", encoding="utf-8") as file:
            seed_payload = json.load(file)
        seed_cases = seed_payload if isinstance(seed_payload, list) else []
    else:
        seed_cases = []

    by_id_seed = {str(case.get("event_id")): case for case in seed_cases}
    by_id_current = {str(case.get("event_id")): case for case in current_cases}
    common_ids = sorted(set(by_id_seed.keys()) & set(by_id_current.keys()))

    tracked_fields = [
        "classification",
        "priority",
        "risk_score",
        "tags",
        "status",
        "escalated",
        "escalation_target",
        "updated_at",
        "escalation_reason",
    ]

    changed_details: list[dict[str, Any]] = []
    for event_id in common_ids:
        seed_case = by_id_seed[event_id]
        current_case = by_id_current[event_id]

        changes = {}
        for field in tracked_fields:
            if seed_case.get(field) != current_case.get(field):
                changes[field] = {
                    "before": seed_case.get(field),
                    "after": current_case.get(field),
                }

        if changes:
            changed_details.append(
                {
                    "event_id": event_id,
                    "changes": changes,
                }
            )

    classified_non_unknown = sum(
        1 for case in current_cases if str(case.get("classification", "unknown")).lower() != "unknown"
    )
    status_not_new = sum(1 for case in current_cases if str(case.get("status", "new")).lower() != "new")
    updated_at_count = sum(1 for case in current_cases if case.get("updated_at"))

    return {
        "seed_count": len(seed_cases),
        "current_count": len(current_cases),
        "changed_records": len(changed_details),
        "classified_non_unknown": classified_non_unknown,
        "status_not_new": status_not_new,
        "updated_at_count": updated_at_count,
        "samples": changed_details[: max(1, limit)],
    }


def triage_cases_by_origin(origin: str, limit: int = 100) -> dict[str, Any]:
    """Classify and update existing triage DB records filtered by origin keyword."""
    normalized_origin = origin.strip().lower()
    if not normalized_origin:
        return {
            "origin": origin,
            "matched": 0,
            "eligible_new": 0,
            "already_processed": 0,
            "processed": 0,
            "escalated": 0,
            "remaining_new": 0,
            "updated_event_ids": [],
            "results": [],
        }

    safe_limit = max(1, min(limit, 200))
    cases = _load_db()

    def _matches(case: dict[str, Any]) -> bool:
        haystack = " ".join(
            [
                str(case.get("event_type") or ""),
                str(case.get("source") or ""),
                str(case.get("src_ip") or ""),
                str(case.get("dst_ip") or ""),
                str(case.get("raw_log") or ""),
                str(case.get("description") or ""),
            ]
        ).lower()
        return normalized_origin in haystack

    matched_indices = [index for index, case in enumerate(cases) if _matches(case)]

    def _is_unprocessed(case: dict[str, Any]) -> bool:
        status = str(case.get("status", "new")).lower()
        classification = str(case.get("classification", "unknown")).lower()
        return status == "new" and classification == "unknown" and not case.get("updated_at")

    eligible_indices = [index for index in matched_indices if _is_unprocessed(cases[index])]
    selected_indices = eligible_indices[:safe_limit]
    already_processed = len(matched_indices) - len(eligible_indices)

    updated_event_ids: list[str] = []
    results: list[dict[str, Any]] = []

    for index in selected_indices:
        case = cases[index]
        analysis = analyze_event(case, abuse_score=int(case.get("abuse_score", 0) or 0))

        case["classification"] = analysis["classification"]
        case["priority"] = analysis["priority"]
        case["risk_score"] = analysis["risk_score"]
        case["tags"] = analysis["tags"]
        case["escalated"] = analysis["escalation"]["required"]
        case["escalation_target"] = analysis["escalation"]["target_queue"]
        case["status"] = "escalated" if analysis["escalation"]["required"] else "triaged"
        case["updated_at"] = _now_iso()

        event_id = str(case.get("event_id") or "")
        updated_event_ids.append(event_id)
        results.append(
            {
                "event_id": event_id,
                "classification": case["classification"],
                "priority": case["priority"],
                "risk_score": case["risk_score"],
                "escalated": case["escalated"],
                "status": case["status"],
            }
        )

    if selected_indices:
        _save_db(cases)

    escalated_count = sum(1 for item in results if bool(item.get("escalated")))
    return {
        "origin": origin,
        "matched": len(matched_indices),
        "eligible_new": len(eligible_indices),
        "already_processed": already_processed,
        "processed": len(results),
        "escalated": escalated_count,
        "remaining_new": max(0, len(eligible_indices) - len(selected_indices)),
        "updated_event_ids": updated_event_ids,
        "results": results,
    }
