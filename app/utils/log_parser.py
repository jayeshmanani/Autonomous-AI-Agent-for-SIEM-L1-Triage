"""Regex and parsing utilities for SIEM event processing."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
MITRE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def extract_ip(text: str | None) -> str | None:
	"""Extract the first IPv4 address from free text."""
	if not text:
		return None
	match = IPV4_PATTERN.search(text)
	return match.group(0) if match else None


def extract_ips_from_event(event: dict[str, Any]) -> list[str]:
	"""Collect all unique IPv4 addresses observed in common event fields."""
	values: list[str] = []
	candidate_fields = ("src_ip", "dst_ip", "ip", "source_ip", "destination_ip", "raw_log", "description")

	for field in candidate_fields:
		value = event.get(field)
		if isinstance(value, str):
			values.extend(IPV4_PATTERN.findall(value))

	seen: set[str] = set()
	unique_values: list[str] = []
	for value in values:
		if value not in seen:
			seen.add(value)
			unique_values.append(value)
	return unique_values


def extract_mitre_ids(text: str | None) -> list[str]:
	if not text:
		return []
	return sorted({item.upper() for item in MITRE_PATTERN.findall(text)})


def parse_cef_header(raw_log: str | None) -> dict[str, str]:
	"""Parse common CEF header fields when present."""
	if not raw_log or not raw_log.startswith("CEF:"):
		return {}

	# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	parts = raw_log.split("|", 7)
	if len(parts) < 7:
		return {}

	return {
		"cef_vendor": parts[1].strip(),
		"cef_product": parts[2].strip(),
		"cef_device_version": parts[3].strip(),
		"cef_signature_id": parts[4].strip(),
		"cef_name": parts[5].strip(),
		"cef_severity": parts[6].strip(),
	}


def normalize_event(input_event: str | dict[str, Any]) -> dict[str, Any]:
	"""Normalize inbound payload into a consistent event object."""
	if isinstance(input_event, str):
		raw_log = input_event
		base_event: dict[str, Any] = {
			"raw_log": raw_log,
			"description": raw_log,
			"severity": "medium",
			"event_type": "unknown",
		}
	else:
		base_event = dict(input_event)
		raw_log = str(base_event.get("raw_log") or base_event.get("description") or "")
		base_event.setdefault("raw_log", raw_log)
		base_event.setdefault("description", raw_log)
		base_event.setdefault("severity", "medium")
		base_event.setdefault("event_type", "unknown")

	base_event.update(parse_cef_header(raw_log))
	if not base_event.get("src_ip"):
		base_event["src_ip"] = extract_ip(raw_log)
	base_event["ips"] = extract_ips_from_event(base_event)
	base_event["mitre_techniques"] = extract_mitre_ids(
		" ".join(
			[
				str(base_event.get("description") or ""),
				str(base_event.get("additional_info") or ""),
				str(base_event.get("raw_log") or ""),
			]
		)
	)
	return base_event


def load_events(dataset_path: str | Path, max_records: int = 0) -> list[dict[str, Any]]:
	"""Load events from either JSON array or JSON-lines format."""
	path = Path(dataset_path)
	if not path.exists():
		return []

	def _load_linewise(file_obj: Any) -> list[dict[str, Any]]:
		events_linewise: list[dict[str, Any]] = []
		for line in file_obj:
			stripped = line.strip()
			if not stripped:
				continue
			if stripped.endswith(","):
				stripped = stripped[:-1]
			if stripped in {"[", "]"}:
				continue
			try:
				parsed_line = json.loads(stripped)
			except json.JSONDecodeError:
				continue
			if isinstance(parsed_line, dict):
				events_linewise.append(normalize_event(parsed_line))
				if max_records and len(events_linewise) >= max_records:
					break
		return events_linewise

	with path.open("r", encoding="utf-8") as f:
		first_char = ""
		while True:
			char = f.read(1)
			if not char:
				break
			if not char.isspace():
				first_char = char
				break

		f.seek(0)
		events: list[dict[str, Any]] = []

		if first_char == "[":
			try:
				parsed = json.load(f)
			except json.JSONDecodeError:
				f.seek(0)
				return _load_linewise(f)

			if isinstance(parsed, list):
				for item in parsed:
					if isinstance(item, dict):
						events.append(normalize_event(item))
						if max_records and len(events) >= max_records:
							break
				return events
			return []

		return _load_linewise(f)
