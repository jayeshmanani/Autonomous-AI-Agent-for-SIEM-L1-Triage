"""Logic for threat intelligence IP lookups."""

from __future__ import annotations

import os
from functools import lru_cache

import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


@lru_cache(maxsize=2048)
def get_ip_reputation(ip: str | None) -> int:
    """Return AbuseIPDB confidence score in [0, 100]."""
    if not ip:
        return 0

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return 0

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=8)
        response.raise_for_status()
        payload = response.json()
        score = int(payload.get("data", {}).get("abuseConfidenceScore", 0))
        return max(0, min(100, score))
    except Exception:
        return 0