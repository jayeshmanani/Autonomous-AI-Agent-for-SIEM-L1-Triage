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


VT_URL = "https://www.virustotal.com/api/v3/search"

@lru_cache(maxsize=2048)
def get_vt_reputation(indicator: str | None) -> int:
    """Return VirusTotal aggregated malicious score in [0, 100] for IP, Hash, Domain, or URL."""
    if not indicator:
        return 0

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return 0

    headers = {"x-apikey": api_key, "Accept": "application/json"}
    params = {"query": indicator}

    try:
        response = requests.get(VT_URL, headers=headers, params=params, timeout=8)
        response.raise_for_status()
        data = response.json().get("data", [])
        if not data:
            return 0
            
        stats = data[0].get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        harmless = int(stats.get("harmless", 0))
        
        total = malicious + suspicious + undetected + harmless
        if total == 0:
            return 0
            
        score = ((malicious + suspicious) / total) * 100
        return max(0, min(100, int(score)))
    except Exception:
        return 0