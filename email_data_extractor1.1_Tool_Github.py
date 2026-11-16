#!/usr/bin/env python3

import sys
import os
import json
import subprocess
from collections import Counter
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import tempfile

# =====================================================
# Cross-Platform Tool Paths (Relative to script directory)
# =====================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DOMAIN_ANALYZER_PATH = os.path.join(
    BASE_DIR, "Main Code Files", "Domain Analyzer", "domain_risk_analyzer.py"
)

ATTACHMENT_EXTRACTOR_PATH = os.path.join(
    BASE_DIR, "Main Code Files", "Attachment Analysis", "attachment_analyzer.py"
)

IP_ANALYZER_PATH = os.path.join(
    BASE_DIR, "Main Code Files", "IP Analyzer", "ip_analyzer.py"
)

URL_ANALYZER_PATH = os.path.join(
    BASE_DIR, "Main Code Files", "URL Analyzer", "URL_Analyzer.py"
)


IGNORED_DOMAINS = {"fonts.gstatic.com", "fonts.googleapis.com", "w3.org", "schema.org", "schemas.microsoft.com"}
IGNORED_EXTENSIONS = ('.css', '.woff', '.woff2', '.ttf', '.eot', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico')

# Terminal Colors
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def extract_sender_domain(from_header: str) -> str:
    """Extracts clean domain from the email From header using regex."""
    if not from_header:
        return None
    from_str = str(from_header)
    bracket_match = re.search(r'<([^>]+)>', from_str)
    if bracket_match:
        email_candidate = bracket_match.group(1).strip()
        if "@" in email_candidate:
            return email_candidate.split("@")[-1].lower().strip()
            
    email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', from_str)
    if email_match:
        return email_match.group(0).split("@")[-1].lower().strip()
        
    return None


def extract_urls_with_counts(msg) -> tuple[list, dict, set]:
    """
    Robustly traverses all MIME content types (single-part, multipart/mixed, 
    multipart/alternative, multipart/related, etc.) to extract body URLs.
    """
    raw_found_urls = []
    encountered_content_types = set()
    unknown_structures = set()

    for part in msg.walk():
        content_type = part.get_content_type()
        encountered_content_types.add(content_type)
        
        main_type = part.get_content_maintype()
        sub_type = part.get_content_subtype()

        # Track or warn on uncommon/unrecognized MIME types dynamically
        standard_types = {
            'text/plain', 'text/html', 'multipart/mixed', 
            'multipart/alternative', 'multipart/related', 
            'multipart/signed', 'multipart/encrypted'
        }
        if content_type not in standard_types and main_type != 'multipart':
            unknown_structures.add(content_type)

        # Skip multipart container nodes directly
        if main_type == 'multipart':
            continue
            
        content_disposition = str(part.get("Content-Disposition", ""))
        # Skip attachments for body URL extraction (handled separately)
        if "attachment" in content_disposition:
            continue
            
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            decoded = payload.decode(errors="ignore")
        except Exception:
            continue
            
        if content_type == "text/html":
            soup = BeautifulSoup(decoded, 'html.parser')
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                if href.startswith(("http://", "https://")):
                    raw_found_urls.append(href)
                    
        elif content_type == "text/plain":
            url_pattern = r'https?://[^\s<>"]+'
            matches = re.findall(url_pattern, decoded)
            for m in matches:
                raw_found_urls.append(m)
                
    filtered_urls = []
    for url in raw_found_urls:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain in IGNORED_DOMAINS or any(domain.endswith("." + d) for d in IGNORED_DOMAINS):
                continue
            if parsed.path.lower().endswith(IGNORED_EXTENSIONS):
                continue
            filtered_urls.append(url)
        except Exception:
            pass

    counts = Counter(filtered_urls)
    unique_urls = list(dict.fromkeys(filtered_urls))
    return unique_urls, dict(counts), list(unknown_structures)


def extract_and_save_attachments(msg) -> list:
    """Extracts email attachments from any multipart container and saves them to /tmp."""
    saved_attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        content_disposition = str(part.get("Content-Disposition", ""))
        
        # Check explicit attachment dispositions or parts with filenames
        if filename or "attachment" in content_disposition:
            if not filename:
                filename = "unnamed_attachment.bin"
            clean_filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
            save_path = os.path.join(tempfile.gettempdir(), clean_filename)
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    with open(save_path, "wb") as f:
                        f.write(payload)
                    saved_attachments.append(save_path)
            except Exception:
                pass
    return saved_attachments


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def extract_ips(text: str) -> list:
    ips = set()
    bracket_ip_pattern = r'\[((?:\d{1,3}\.){3}\d{1,3})\]'
    sender_ip_pattern = r"Sender IP is\s*((?:\d{1,3}\.){3}\d{1,3})"
    fallback_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    
    ips.update(re.findall(bracket_ip_pattern, text))
    ips.update(re.findall(sender_ip_pattern, text))
    if not ips:
        ips.update(re.findall(fallback_pattern, text))
    return list(ips)


def get_originating_ip(headers) -> str:
    received_headers = headers.get_all("Received", [])
    for line in reversed(received_headers):
        ips = extract_ips(line)
        if ips:
            return ips[0]
    return "Not Found"


def analyze_eml(eml_path: str):
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = msg
    raw_headers = str(headers)

    # =====================================================
    # STEP 1: Header Authentication & Ingestion
    # =====================================================
    unique_urls, url_counts, unknown_structures = extract_urls_with_counts(msg)
    saved_attachments = extract_and_save_attachments(msg)

    spf = str(headers.get("Received-SPF", "Not Found"))
    dkim = "Present" if headers.get("DKIM-Signature") else "Missing"
    dmarc = str(headers.get("Authentication-Results", "Not Found"))

    auth_passed = True
    if "fail" in spf.lower() or "fail" in dmarc.lower() or dkim == "Missing":
        auth_passed = False

    originating_ip = get_originating_ip(headers)

    print(f"{CYAN}\n================ EMAIL ANALYSIS REPORT ================\n{RESET}")
    print(f"{YELLOW}[ Basic Information ]{RESET}")
    print(f"From        : {headers.get('From', 'N/A')}")
    print(f"To          : {headers.get('To', 'N/A')}")
    print(f"Reply-To    : {headers.get('Reply-To', 'N/A')}")
    print(f"Delivered-To: {headers.get('Delivered-To', 'N/A')}")
    print(f"Subject     : {headers.get('Subject', 'N/A')}")
    print(f"Date        : {headers.get('Date', 'N/A')}")
    
    message_id = headers.get('Message-ID', 'N/A')
    print(f"Message-ID  : {message_id}")
    
    # Extract domain from Message-ID
    msg_id_domain_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', str(message_id))
    msg_id_domain = msg_id_domain_match.group(1) if msg_id_domain_match else "N/A"
    print(f"Message-ID Domain: {msg_id_domain}")

    # Custom Header Check
    custom_header = headers.get("X-Custom-Header", None)
    if custom_header:
        print(f"X-Custom-Header : {GREEN}{custom_header}{RESET}")

    print(f"Attachments : {len(saved_attachments)} File(s) Detected")

    # Notification for unknown structures
    if unknown_structures:
        print(f"\n{RED}[!] NOTIFICATION: Unrecognized or Custom Content-Type(s) Detected:{RESET}")
        for unk in unknown_structures:
            print(f"    - Type: {unk} (Ensure parsing logic covers this format if specialized data is required)")

    print(f"{YELLOW}\n[ Extracted IPs (Defanged) ]{RESET}")
    defanged_ips = [defang_ip(ip) for ip in extract_ips(raw_headers)]
    if defanged_ips:
        for ip in defanged_ips:
            print(f" - {ip}")
    else:
        print("None Found")

    print(f"{YELLOW}\n[ Header Authentication ]{RESET}")
    print(f"SPF   : {spf}")
    print(f"DKIM  : {dkim}")
    print(f"DMARC : {dmarc}")
    print(f"Auth Status : {GREEN + 'PASS' if auth_passed else RED + 'FAIL'}{RESET}")

    print(f"{YELLOW}\n[ Extracted Body URLs ({len(unique_urls)} Unique) ]{RESET}")
    if unique_urls:
        for u in unique_urls:
            count = url_counts.get(u, 1)
            count_str = f"(Found {count} times in body)" if count > 1 else "(Found 1 time)"
            print(f" - {u} {CYAN}{count_str}{RESET}")
    else:
        print("No URLs detected in body")

    print(f"{YELLOW}\n[ Originating IP ]{RESET}")
    print(defang_ip(originating_ip))

    # =====================================================
    # STEP 2: Domain Analysis (Sender + Body Link)
    # =====================================================
    sender_domain = extract_sender_domain(headers.get("From", ""))
    body_url_domain = urlparse(unique_urls[0]).netloc.lower() if unique_urls else None

    domains_to_analyze = {}
    if sender_domain:
        domains_to_analyze["sender_domain"] = sender_domain
    if body_url_domain:
        domains_to_analyze["body_url_domain"] = body_url_domain
    if msg_id_domain != "N/A" and msg_id_domain not in domains_to_analyze.values():
        domains_to_analyze["message_id_domain"] = msg_id_domain

    domain_enrichment_results = {}

    print(f"{YELLOW}\n[ STEP 2: Domain Analysis ]{RESET}")
    for source_type, domain_name in domains_to_analyze.items():
        print(f"[*] Invoking Domain Analyzer for ({source_type}): {CYAN}{domain_name}{RESET}")
        try:
            cmd = [sys.executable, DOMAIN_ANALYZER_PATH, domain_name]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.stdout.strip():
                res_json = json.loads(proc.stdout.strip())
                domain_enrichment_results[source_type] = res_json

                risk = res_json.get("overall_risk_level", "UNKNOWN")
                status = res_json.get("risk_status", "UNKNOWN")
                color = GREEN if risk == "LOW" else RED
                print(f"    >> [{source_type.upper()}] Verdict: {color}{risk}{RESET} ({status})")
            else:
                domain_enrichment_results[source_type] = {"error": f"Domain tool output empty. Stderr: {proc.stderr.strip()}"}

        except Exception as e:
            domain_enrichment_results[source_type] = {"error": f"Domain Analysis failed: {str(e)}"}

    # =====================================================
    # STEP 2.5: IP WHOIS & RDAP Lookup
    # =====================================================
    ip_enrichment_results = {}
    if originating_ip and originating_ip != "Not Found":
        print(f"{YELLOW}\n[ STEP 2.5: IP WHOIS & RDAP Lookup ]{RESET}")
        print(f"[*] Querying Network & Contact Telemetry for: {CYAN}{defang_ip(originating_ip)}{RESET}")
        try:
            cmd = [sys.executable, IP_ANALYZER_PATH, originating_ip]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.stdout.strip():
                ip_res_json = json.loads(proc.stdout.strip())
                ip_enrichment_results["originating_ip_telemetry"] = ip_res_json
                print(f"{GREEN}[+] RDAP IP Lookup Complete ({ip_res_json.get('net_name', 'N/A')} - {ip_res_json.get('customer_org', 'N/A')}){RESET}")
            else:
                ip_enrichment_results["originating_ip_telemetry"] = {"error": f"IP tool output empty. Stderr: {proc.stderr.strip()}"}
        except Exception as e:
            ip_enrichment_results["originating_ip_telemetry"] = {"error": f"IP WHOIS lookup failed: {str(e)}"}

    # =====================================================
    # STEP 3: Attachment Content & OCR Analysis
    # =====================================================
    attachment_results = []
    attachment_extracted_urls = []

    if saved_attachments:
        print(f"{YELLOW}\n[ STEP 3: Attachment Content Analysis ]{RESET}")
        for attach_path in saved_attachments:
            print(f"[*] Analyzing Content & OCR for: {CYAN}{os.path.basename(attach_path)}{RESET}")
            try:
                cmd = [sys.executable, ATTACHMENT_EXTRACTOR_PATH, attach_path]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.stdout.strip():
                    attach_data = json.loads(proc.stdout.strip())
                    attachment_results.append(attach_data)

                    found_urls = attach_data.get("all_extracted_urls") or attach_data.get("extracted_urls") or []
                    if found_urls:
                        print(f"{RED}[!] Discovered {len(found_urls)} URL(s) inside attachment!{RESET}")
                        attachment_extracted_urls.extend(found_urls)
            except Exception as e:
                attachment_results.append({"file": attach_path, "error": str(e)})
    else:
        print(f"{YELLOW}\n[ STEP 3: Attachment Content Analysis ]{RESET}")
        print("No attachments present in email.")

    all_combined_urls = list(dict.fromkeys(unique_urls + attachment_extracted_urls))

    # =====================================================
    # STEP 4: Multi-API URL Analysis
    # =====================================================
    url_enrichment = None
    secondary_urls_warning = None

    print(f"{YELLOW}\n[ STEP 4: Multi-API URL Analysis ]{RESET}")
    if all_combined_urls:
        primary_url = all_combined_urls[0]
        secondary_urls = all_combined_urls[1:]

        print(f"[*] Candidate URLs Detected ({len(all_combined_urls)} Total).")
        print(f"[*] Running Multi-API Analysis on Primary Target: {CYAN}{primary_url}{RESET}")
        
        try:
            cmd = [sys.executable, URL_ANALYZER_PATH, primary_url]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            
            raw_stdout = proc.stdout.strip()
            if raw_stdout:
                try:
                    url_enrichment = json.loads(raw_stdout)
                except json.JSONDecodeError:
                    url_enrichment = {"error": "URL tool returned non-JSON output", "raw_output": raw_stdout}
            else:
                url_enrichment = {"error": "URL tool returned empty output."}
        except Exception as e:
            url_enrichment = {"error": f"Failed to run URL tool: {str(e)}"}

        if secondary_urls:
            is_malicious = False
            if isinstance(url_enrichment, dict):
                verdict = str(url_enrichment.get("verdict", "")).upper()
                if "MALICIOUS" in verdict or "SUSPICIOUS" in verdict:
                    is_malicious = True

            recommendation = (
                "URGENT: Primary URL flagged suspicious/malicious! Secondary URLs MUST be investigated manually."
                if is_malicious else
                "NOTICE: Primary URL passed clean. Secondary URLs recommended for separate manual inspection."
            )

            secondary_urls_warning = {
                "total_secondary_count": len(secondary_urls),
                "unscanned_urls": secondary_urls,
                "investigation_guidance": recommendation
            }

            print(f"\n{RED if is_malicious else YELLOW}[!] SECONDARY URL NOTICE [{len(secondary_urls)} Additional Link(s) Flagged]:{RESET}")
            for sec in secondary_urls:
                print(f"    - {sec}")
    else:
        print("No actionable URLs found in body or attachments.")

    # =====================================================
    # STEP 5: Aggregated SOAR JSON Output (Wazuh)
    # =====================================================
    severity = "LOW"
    if not auth_passed and all_combined_urls:
        severity = "CRITICAL"
    elif not auth_passed or all_combined_urls or saved_attachments:
        severity = "HIGH"

    soar_payload = {
        "alert_severity": severity,
        "subject": headers.get("Subject", "N/A"),
        "from": headers.get("From", "N/A"),
        "sender_domain": sender_domain,
        "message_id_domain": msg_id_domain,
        "custom_header": custom_header,
        "unrecognized_content_types": unknown_structures,
        "auth_passed": auth_passed,
        "has_attachments": len(saved_attachments) > 0,
        "attachment_count": len(saved_attachments),
        "domain_analysis": domain_enrichment_results,
        "ip_analysis": ip_enrichment_results,
        "attachment_analysis": attachment_results,
        "primary_analyzed_url": all_combined_urls[0] if all_combined_urls else None,
        "url_occurrences": url_counts,
        "originating_ip": defang_ip(originating_ip),
        "url_enrichment": url_enrichment,
        "secondary_urls_notice": secondary_urls_warning
    }

    print(f"{GREEN}\n================ ANALYSIS COMPLETE ===================={RESET}\n")
    print(f"{CYAN}[ Final SOAR Pipeline Payload (Wazuh Alert) ]{RESET}")
    print(json.dumps(soar_payload, indent=2))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 email_data_extractor.py <file.eml>")
        sys.exit(1)
        
    analyze_eml(sys.argv[1])