#!/usr/bin/env python3

import base64
import os
import sys
import json
import ipaddress
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(BASE_DIR, "api_keys.env")
load_dotenv(dotenv_path=env_path)

# =====================================================
# Helper: Environment Sanitizer
# =====================================================
def get_clean_env(var_name: str) -> str:
    """Retrieve environment variable and strip extraneous quotes/spaces."""
    raw_val = os.getenv(var_name, "")
    return raw_val.strip().strip('"').strip("'")


# =====================================================
# Engine 1: VirusTotal API v3
# =====================================================

def check_virustotal(target_url: str) -> dict:
    api_key = get_clean_env("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "status": "SKIPPED",
            "reason": "VIRUSTOTAL_API_KEY missing"
        }

    # Encode the complete URL for VirusTotal API v3
    url_id = base64.urlsafe_b64encode(
        target_url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            attributes = response.json().get(
                "data", {}
            ).get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})

            if not stats:
                return {
                    "status": "INCONCLUSIVE",
                    "reason": "No analysis statistics available"
                }

            return {
                "status": "SUCCESS",
                "lookup_type": "FULL_URL",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "last_analysis_date": attributes.get(
                    "last_analysis_date"
                ),
                "reputation": attributes.get("reputation"),
                "categories": attributes.get("categories", {})
            }

        if response.status_code == 404:
            return {
                "status": "NOT_FOUND",
                "reason": "No existing VirusTotal report for this URL"
            }

        if response.status_code == 429:
            return {
                "status": "UNAVAILABLE",
                "reason": "VirusTotal API rate limit exceeded"
            }

        if response.status_code in (401, 403):
            return {
                "status": "UNAVAILABLE",
                "reason": "VirusTotal authentication or permission error"
            }

        return {
            "status": "ERROR",
            "reason": f"HTTP {response.status_code}"
        }

    except requests.RequestException as error:
        return {
            "status": "ERROR",
            "reason": str(error)
        }



# =====================================================
# Engine 2: URLhaus API (abuse.ch)
# =====================================================
def check_urlhaus(url_to_check: str) -> dict:
    api_key = get_clean_env("URLHAUS_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "URLHAUS_API_KEY missing"}

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    
    # Custom Auth-Key header required by abuse.ch
    headers = {
        "Auth-Key": api_key
    }
    data = {
        "url": url_to_check
    }

    try:
        res = requests.post(api_url, data=data, headers=headers, timeout=6)
        if res.status_code == 200:
            result = res.json()
            query_status = result.get("query_status")
            
            if query_status == "ok":
                return {
                    "status": "MALICIOUS",
                    "threat": result.get("threat", "malware"),
                    "tags": result.get("tags", [])
                }
            elif query_status == "no_results":
                return {"status": "NOT_LISTED"}
            else:
                return {"status": "ERROR", "reason": f"URLhaus Status: {query_status}"}
        elif res.status_code == 401 or res.status_code == 403:
            return {"status": "ERROR", "reason": "HTTP 401/403: Invalid URLhaus Auth-Key"}
        else:
            return {"status": "ERROR", "reason": f"HTTP {res.status_code}"}
            
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}
    
# =====================================================
# Engine 3: URLScan.io API
# =====================================================
def check_urlscan_history(domain: str) -> dict:
    api_key = get_clean_env("URLSCAN_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "URLSCAN_API_KEY missing"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    query = f"page.domain:{domain} OR task.domain:{domain}"
    search_url = f"https://urlscan.io/api/v1/search/?q={query}"

    try:
        res = requests.get(search_url, headers=headers, timeout=6)
        if res.status_code != 200:
            return {"status": "ERROR", "reason": f"Search HTTP {res.status_code}"}

        search_data = res.json()
        results = search_data.get("results", [])
        if not results:
            return {"status": "NOT_LISTED", "historical_malicious_scans": 0}

        latest_scan_uuid = results[0].get("_id") or results[0].get("task", {}).get("uuid")
        if not latest_scan_uuid:
            return {"status": "ERROR", "reason": "No UUID found"}

        result_url = f"https://urlscan.io/api/v1/result/{latest_scan_uuid}/"
        res_full = requests.get(result_url, headers=headers, timeout=6)
        
        if res_full.status_code == 200:
            full_data = res_full.json()
            verdicts = full_data.get("verdicts", {})
            overall = verdicts.get("overall", {})
            urlscan_v = verdicts.get("urlscan", {})

            is_malicious = (
                overall.get("malicious") is True or
                urlscan_v.get("malicious") is True or
                overall.get("score", 0) > 0
            )

            return {
                "status": "SUCCESS",
                "historical_malicious_scans": 1 if is_malicious else 0,
                "score": overall.get("score", 0),
                "categories": overall.get("categories", []),
                "brands": overall.get("brands", []),
                "scan_uuid": latest_scan_uuid
            }
        return {"status": "ERROR", "reason": f"Result HTTP {res_full.status_code}"}

    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}

# =====================================================
# Engine 4: CRDF Threat Center (read-only URL lookup)
# =====================================================
def check_crdf(target_url: str) -> dict:
    api_key = get_clean_env("CRDF_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "CRDF_API_KEY missing"}

    endpoint = "https://threatcenter.crdf.fr/api/v1/search_urls.json"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    try:
        res = requests.post(
            endpoint,
            headers=headers,
            json={"method": "search_urls", "urls": [target_url]},
            timeout=10,
        )
        if res.status_code == 401:
            return {"status": "ERROR", "reason": "CRDF authentication failed (401)"}
        if res.status_code == 403:
            return {"status": "UNAVAILABLE", "reason": "CRDF key lacks lookup permission (403); private CTI access may be required"}
        if res.status_code == 429:
            return {"status": "ERROR", "reason": "CRDF rate limit exceeded (429)"}
        if res.status_code != 200:
            return {"status": "ERROR", "reason": f"CRDF HTTP {res.status_code}"}
        body = res.json()
        if body.get("error"):
            code = body.get("error_code", "unknown")
            return {"status": "UNAVAILABLE" if code == "MissingPermission" else "ERROR",
                    "reason": f"CRDF API: {code}"}
        entries = body.get("data")
        if not isinstance(entries, list) or not entries:
            return {"status": "UNKNOWN", "reason": "No lookup entries returned"}
        item = entries[0]
        if item.get("error"):
            return {"status": "UNKNOWN", "reason": item.get("message", "Lookup error")}
        if item.get("in_database") is False:
            return {"status": "NOT_LISTED", "reason": "Not found in CRDF database; not proof of safety"}
        if item.get("in_database") is not True:
            return {"status": "UNKNOWN", "reason": "No definitive database membership"}
        record = item.get("data") or {}
        blacklisted = str(record.get("isBlacklisted", "")).lower() in ("1", "true")
        return {
            "status": "MALICIOUS" if blacklisted else "LISTED_NOT_BLACKLISTED",
            "category": record.get("category"),
            "listed_url": record.get("url"),
            "is_blacklisted": blacklisted,
        }
    except (requests.RequestException, ValueError) as exc:
        return {"status": "ERROR", "reason": str(exc)}

# =====================================================
# Redirect Unroller
# =====================================================
def trace_redirects(url: str) -> dict:
    """Passive-only: do not visit or follow the submitted URL."""
    return {"initial_url": url, "final_url": url, "redirected": False,
            "note": "Not checked: passive TI-only mode (no direct website requests)"}


# =====================================================
# Correlation & Consensus Engine
# =====================================================
def correlate_url(target_url: str) -> dict:
    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    trace = trace_redirects(target_url)
    final_url = trace["final_url"]
    parsed_url = urlparse(final_url)
    final_domain = parsed_url.netloc.split(":")[0] if parsed_url.netloc else parsed_url.path.split("/")[0]

    # 1. Query All 4 Engines
    raw_reports = {
        "virustotal": check_virustotal(final_url),
        "urlhaus": check_urlhaus(final_url),
        "urlscan": check_urlscan_history(final_domain),
        "crdf": check_crdf(final_url)
    }

    # 2. Aggregate detections. API errors and unavailable engines never vote clean.
    malicious_indicators = 0
    flags = []
    metrics = {
        "total_tools_run": len(raw_reports),
        "malicious_count": 0,
        "clean_count": 0,  # Legacy field: successful lookups without malicious findings
        "error_or_skipped_count": 0,
    }
    suspicious_count = 0

    vt = raw_reports["virustotal"]
    if vt.get("status") == "SUCCESS":
        if vt.get("malicious", 0) > 0:
            malicious_indicators += 2
            metrics["malicious_count"] += 1
            flags.append(f"VirusTotal: {vt['malicious']} engines flagged the host as malicious")
        elif vt.get("suspicious", 0) > 0:
            suspicious_count += 1
            flags.append(f"VirusTotal: {vt['suspicious']} engines marked the host suspicious")
        else:
            metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    uh = raw_reports["urlhaus"]
    if uh.get("status") == "MALICIOUS":
        malicious_indicators += 2
        metrics["malicious_count"] += 1
        flags.append(f"URLhaus threat match: {uh.get('threat')}")
    elif uh.get("status") in ("CLEAN", "NOT_LISTED"):
        metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    us = raw_reports["urlscan"]
    if us.get("status") == "SUCCESS":
        if us.get("historical_malicious_scans", 0) > 0:
            malicious_indicators += 2
            metrics["malicious_count"] += 1
            flags.append(f"URLScan.io historical malicious verdict (score: {us.get('score')})")
        else:
            metrics["clean_count"] += 1
    elif us.get("status") in ("CLEAN", "NOT_LISTED"):
        metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    crdf = raw_reports["crdf"]
    if crdf.get("status") == "MALICIOUS":
        malicious_indicators += 2
        metrics["malicious_count"] += 1
        flags.append(f"CRDF blacklisted URL (category: {crdf.get('category')})")
    elif crdf.get("status") in ("NOT_LISTED", "LISTED_NOT_BLACKLISTED"):
        metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    if malicious_indicators > 0:
        verdict = "MALICIOUS"
    elif suspicious_count > 0:
        verdict = "SUSPICIOUS"
    elif metrics["clean_count"] > 0:
        verdict = "NO_KNOWN_THREATS"
    else:
        verdict = "INCONCLUSIVE"

    return {
        "url_trace": trace,
        "final_domain": final_domain,
        "verdict": verdict,
        "threat_score": malicious_indicators,
        "engine_summary": metrics,
        "triggered_flags": flags,
        "raw_engine_reports": raw_reports
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python3 URL_Analyzer.py <URL>"}))
        sys.exit(1)

    url_to_test = sys.argv[1]
    report = correlate_url(url_to_test)
    print(json.dumps(report, indent=2))