"""Optional manual IP lookup. No automatic bulk enrichment or API-key persistence."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from netstat_monitor import is_public_ip


API_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"


def lookup_ip(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    if not is_public_ip(ip):
        raise ValueError("Only globally routable IPs can be submitted for reputation checks.")
    if not api_key or not api_key.strip():
        raise ValueError("Enter your AbuseIPDB API key to look up an IP.")
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    request = urllib.request.Request(
        f"{API_ENDPOINT}?{query}",
        headers={"Key": api_key.strip(), "Accept": "application/json", "User-Agent": "PythonProject002-NetstatInvestigator/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            data = json.load(response).get("data")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError(f"AbuseIPDB declined the API key/request (HTTP {exc.code}).") from exc
        if exc.code == 429:
            raise RuntimeError("AbuseIPDB rate limit exceeded. Retry later.") from exc
        raise RuntimeError(f"AbuseIPDB returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Network error during reputation lookup: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Reputation service returned an unexpected response.")
    return data


def summarize_reputation(result: dict) -> str:
    score = result.get("abuseConfidenceScore", "unknown")
    reports = result.get("totalReports", "unknown")
    return (
        f"AbuseIPDB (past 90 days): score {score}/100, reports {reports}. "
        f"ISP: {result.get('isp') or 'unknown'}; country: {result.get('countryCode') or 'unknown'}. "
        "Crowdsourced reports may be inaccurate; a zero score does not prove an IP safe."
    )
