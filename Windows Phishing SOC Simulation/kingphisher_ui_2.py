#!/usr/bin/env python3
"""
THE KINGPHISHER-MAN  -  local web UI for the Phishing SOC simulator
====================================================================
Pure standard library (no pip installs needed for the UI itself).  It opens in your browser:
    python kingphisher_ui.py                 # then it opens http://127.0.0.1:8765
    python kingphisher_ui.py --no-browser    # just print the URL
    python kingphisher_ui.py --reset-quota   # owner/admin: reset the usage counters
    python kingphisher_ui.py --check         # verify the paths below and exit

  A  ROOKIE   : fetch ONE random sample from phishing_pot and analyse it (unlimited runs)
  B  AMATEUR  : upload a .eml and analyse it            (unlimited runs)
  C  PRO      : guard a Gmail inbox live (runs section2_live_guard.py, 2-minute window)

Results are shown as  H·D·I·F  =  Header · Domain · IP lookup · File analysis
(Heuristic Defense & Inspection Framework) + a final combined verdict.
"""

import os
import re
import sys
import json
import hmac
import html
import time
import uuid
import base64
import random
import hashlib
import argparse
import ipaddress
import secrets
import subprocess
import threading
import importlib.util
import urllib.request
import urllib.error
import webbrowser
from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

# =====================================================================
#  >>>  CONFIGURATION  -  put YOUR paths here  <<<
# =====================================================================
# ============================================================
# CONFIGURATION - Dynamic GitHub Repository Paths
# ============================================================

# Directory containing kingphisher_ui_2.py
BASE_DIR = Path(__file__).resolve().parent

# Root directory: The-KingPhisher-Man
ROOT_DIR = BASE_DIR.parent

# Main email analysis tool (located in repository root)
TOOL_SCRIPT = str(
    ROOT_DIR / "email_data_extractor1.1_Tool_Github.py"
)


# 2) The other scripts of the project (leave as-is if they sit next to this file)


GUARD_SCRIPT = BASE_DIR / "section-2_live_guard.py"        # used by the PRO card
# Option 1: Use a raw string (the 'r' prefix prevents \U and other backslashes from being treated as escape characters)

# Domain analyzer
DOMAIN_ANALYZER = (
    ROOT_DIR
    / "Main Code Files"
    / "Domain Analysis"
    / "domain_risk_analyzer.py"
)
HOST, PORT = "127.0.0.1", 8765                            # local only - never bind to 0.0.0.0

# 3) Usage limits per install (0 = unlimited). Enforced server-side + signed state file.
LIMITS = {"demo": 0, "upload": 0, "pro": 0}

# MASTER SWITCH  -  False = NO usage limits at all: Rookie, Amateur and Pro can each be run any number of
# times. The quota code is bypassed completely (no counters, no state file, no "locked" state).
# True  = enforce LIMITS above (a value of 0 still means unlimited for that one mode).
QUOTA_ENABLED = False
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
TOOL_TIMEOUT = 300            # seconds for your analysis tool
PRO_WAIT_SECONDS = 120        # how long the PRO guard waits for the attacker's mail
COOLDOWN_SECONDS = 4          # minimum gap between two analysis starts

# 4) phishing_pot (ROOKIE card)
REPO_OWNER, REPO_NAME, REPO_BRANCH, REPO_DIR = "rf-peixoto", "phishing_pot", "main", "email"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# 5) Scoring zones (risk 0-100)
ZONE_YELLOW, ZONE_RED = 20, 60
WEIGHTS = {"header": 0.25, "domain": 0.40, "ip": 0.15, "file": 0.20}
SEVERITY_FLOOR = {"CRITICAL": 85, "HIGH": 70, "MEDIUM": 40}   # tool's own correlated verdict acts as a floor

DATA_DIR = BASE_DIR / "ui_data"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
STATE_FILE = DATA_DIR / "ui_state.json"
SECRET_FILE = DATA_DIR / ".ui_secret"
LOG_DIR = BASE_DIR / "logs"
REPO_COUNTER_LOG = LOG_DIR / "repo_eml_counter.log"       # shared with section1 (never re-fetch a sample)
UI_DIR = BASE_DIR / "ui"
ASSET_DIR = BASE_DIR / "assets"

# =====================================================================
#  CONSOLE
# =====================================================================
os.system("")
W, G, B, Y, R, X = "\033[97m", "\033[92m", "\033[94m", "\033[93m", "\033[91m", "\033[0m"


def say(color, tag, msg):
    print(f"{color}[{datetime.now():%H:%M:%S}] [{tag}] {msg}{X}", flush=True)


def show_startup_banner():
    print(f"""
{B}============================================================
           THE KINGPHISHER-MAN
          PHISHING SOC SIMULATION
============================================================{X}

{G}  AVAILABLE COMMANDS{X}

  python kingphisher_ui_2.py
      Start the local web interface

  python kingphisher_ui_2.py --no-browser
      Start the server without opening the browser

  python kingphisher_ui_2.py --check
      Verify project files and dependencies

  python kingphisher_ui_2.py --reset-quota
      Reset local usage counters

  python kingphisher_ui_2.py --port 9000
      Launch the interface on a custom port

{Y}  Press Ctrl+C to stop the server.{X}

============================================================
""")


def browser_countdown(url, seconds=5):
    for remaining in range(seconds, 0, -1):
        print(
            f"\r{Y}[STARTUP] Opening browser in "
            f"{remaining} second(s)...{X}",
            end="",
            flush=True
        )
        time.sleep(1)

    print(f"\r{G}[READY] Opening {url}                    {X}")
    webbrowser.open(url)




# =====================================================================
#  SMALL UTILITIES
# =====================================================================
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def clean_text(s, n=300):
    s = ANSI_RE.sub("", str(s))
    s = "".join(ch for ch in s if ch >= " " or ch == "\t")
    return s[:n]


def redact(s, secrets_list=()):
    for sec in secrets_list:
        if sec and len(sec) >= 4:
            s = s.replace(sec, "[redacted]")
    return re.sub(r"[A-Za-z0-9_\-]{40,}", "[redacted]", s)


def zone_of(score):
    if score is None:
        return "na"
    return "green" if score < ZONE_YELLOW else ("yellow" if score < ZONE_RED else "red")


VERDICT_BY_ZONE = {"green": "LOW RISK", "yellow": "SUSPICIOUS", "red": "DANGEROUS", "na": "N/A"}


def card(title, level, lines):
    return {"title": title, "level": level, "lines": [str(l) for l in lines]}


def level_for_points(p, yellow=8, red=25):
    return "red" if p >= red else ("yellow" if p >= yellow else "green")


def safe_get(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
    return default if d is None else d


# =====================================================================
#  OPTIONAL: your domain_risk_analyzer module (loaded lazily, never fatal)
# =====================================================================
_DOM = {"tried": False, "mod": None}


def domain_mod():
    if not _DOM["tried"]:
        _DOM["tried"] = True
        try:
            if DOMAIN_ANALYZER.is_file():
                spec = importlib.util.spec_from_file_location("domain_risk_analyzer", DOMAIN_ANALYZER)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                _DOM["mod"] = mod
        except BaseException:           # the module calls sys.exit() when a dependency is missing
            _DOM["mod"] = None
    return _DOM["mod"]


MINI_BRANDS = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "google": ["google.com", "gmail.com"], "apple": ["apple.com", "icloud.com"], "amazon": ["amazon.com"],
    "netflix": ["netflix.com"], "facebook": ["facebook.com"], "bradesco": ["bradesco.com.br"],
    "livelo": ["livelo.com.br"], "itau": ["itau.com.br"], "santander": ["santander.com"], "dhl": ["dhl.com"],
    "fedex": ["fedex.com"], "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "linkedin": ["linkedin.com"],
}


def brands():
    m = domain_mod()
    return getattr(m, "BRANDS", None) or MINI_BRANDS


def reg_domain(host: str) -> str:
    host = (host or "").lower().strip(".> ")
    m = domain_mod()
    try:
        if m is not None:
            e = m._TLDX(host)
            if e.domain and e.suffix:
                return f"{e.domain}.{e.suffix}"
    except Exception:
        pass
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "ymail.com",
            "aol.com", "proton.me", "protonmail.com", "icloud.com", "gmx.com", "mail.com", "zoho.com"}
URGENT_RE = re.compile(r"urgent|immediately|asap|verify|suspend|expir|password|invoice|payment|gift ?card|unusual|"
                       r"locked|action required|final notice|confirm your|security alert|account.{0,12}(closed|limited)|"
                       r"bonus|pontos|expirando", re.I)
ROLE_WORDS = ("support", "security", "billing", "admin", "helpdesk", "service", "account", "team", "noreply", "verify")


# =====================================================================
#  EXTRACT THE TOOL'S PAYLOAD  (header line + pretty JSON, compact JSON, or YAML)
# =====================================================================
def extract_payload(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("The analysis tool printed nothing")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass
    dec, best, best_len = json.JSONDecoder(), None, 0
    for m in re.finditer(r"(?m)^\{", text):
        try:
            obj, end = dec.raw_decode(text[m.start():])
        except ValueError:
            continue
        if isinstance(obj, dict) and end > best_len:
            best, best_len = obj, end
    if best is not None:
        return best
    try:
        import yaml
        cleaned = "\n".join(l for l in text.splitlines() if not re.match(r"^\s*\[.*\]\s*$", l))
        obj = yaml.safe_load(cleaned)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    raise ValueError("No JSON/YAML payload found in the tool output")


class ToolError(Exception):
    pass


def run_tool(eml_path: Path) -> dict:
    tool = Path(TOOL_SCRIPT)
    if not tool.is_file():
        raise ToolError("Analysis tool not found - set TOOL_SCRIPT at the top of kingphisher_ui.py")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    try:
        p = subprocess.run([sys.executable, str(tool), str(eml_path)], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=TOOL_TIMEOUT, cwd=str(tool.parent), env=env)
    except subprocess.TimeoutExpired:
        raise ToolError(f"The analysis tool timed out after {TOOL_TIMEOUT}s")
    if p.returncode != 0:
        say(R, "tool", f"exit {p.returncode}: {clean_text(p.stderr, 400)}")      # details stay in YOUR console only
        raise ToolError(f"The analysis tool failed (exit code {p.returncode}) - see the server console")
    try:
        return extract_payload(p.stdout)
    except ValueError as e:
        raise ToolError(str(e))


# =====================================================================
#  H  -  HEADER ANALYSIS
# =====================================================================
def analyze_header(raw: bytes, payload):
    try:
        msg = message_from_bytes(raw, policy=policy.default)
    except Exception:
        msg = message_from_bytes(raw)

    def hv(name):
        try:
            v = msg.get(name)
        except Exception:
            v = None
        return re.sub(r"\s+", " ", str(v)).strip() if v is not None else ""

    frm, to, reply, deliv = hv("From"), hv("To"), hv("Reply-To"), hv("Delivered-To")
    ret, subj, date, mid = hv("Return-Path"), hv("Subject"), hv("Date"), hv("Message-ID")
    xmailer = hv("X-Mailer") or hv("User-Agent")
    fname, faddr = parseaddr(frm)
    fdom = faddr.rpartition("@")[2].lower().strip("> ")
    rdom = parseaddr(reply)[1].rpartition("@")[2].lower() if reply else ""
    retdom = parseaddr(ret)[1].rpartition("@")[2].lower() if ret else ""
    mdom = mid.strip("<> ").rpartition("@")[2].lower() if "@" in mid else ""
    try:
        atts = sum(1 for part in msg.walk() if part.get_filename())
    except Exception:
        atts = 0
    hops = len(msg.get_all("Received") or [])

    ars = msg.get_all("Authentication-Results") or []
    ar = str(ars[0]) if ars else ""
    rspf = hv("Received-SPF")
    spf = (re.search(r"\bspf=(\w+)", ar) or re.search(r"^\s*(\w+)", rspf) or [None, None])[1] if (ar or rspf) else None
    dkim = (re.search(r"\bdkim=(\w+)", ar) or [None, None])[1]
    dmarc = (re.search(r"\bdmarc=(\w+)", ar) or [None, None])[1]
    tool_auth = safe_get(payload or {}, "auth_passed")

    checks = []

    def chk(group, name, pts, hit, evidence):
        checks.append({"group": group, "name": name, "points": pts if hit else 0, "hit": bool(hit), "evidence": evidence})

    # ---- authentication ----
    if not (spf or dkim or dmarc):
        if tool_auth is False:
            chk("auth", "Authentication (tool verdict)", 25, True, "The analysis tool reports that email authentication FAILED")
        elif tool_auth is True:
            chk("auth", "Authentication (tool verdict)", 0, False, "The analysis tool reports that authentication passed")
        else:
            chk("auth", "No authentication results in headers", 10, True, "No Authentication-Results / Received-SPF header present")
    else:
        spf_p = {"fail": 20, "softfail": 10, "none": 5, "neutral": 4, "permerror": 8, "temperror": 4}.get((spf or "").lower(), 0)
        dk_p = {"fail": 15, "none": 5, "neutral": 5, "permerror": 8}.get((dkim or "").lower(), 0) if dkim else 5
        dm_p = {"fail": 30, "none": 5, "permerror": 8}.get((dmarc or "").lower(), 0) if dmarc else 5
        chk("auth", f"SPF = {spf or 'absent'}", spf_p, spf_p > 0, "Sender IP vs. the domain's SPF policy")
        chk("auth", f"DKIM = {dkim or 'absent'}", dk_p, dk_p > 0, "Cryptographic signature of the message")
        chk("auth", f"DMARC = {dmarc or 'absent'}", dm_p, dm_p > 0, "Alignment of From domain with SPF/DKIM")

    # ---- sender identity ----
    reg_f = reg_domain(fdom)
    if rdom and reg_domain(rdom) != reg_f:
        chk("identity", "Reply-To differs from From", 20, True, f"From @{fdom}  vs  Reply-To @{rdom} - replies are redirected elsewhere")
    else:
        chk("identity", "Reply-To differs from From", 0, False, "Reply-To absent or identical domain")
    if retdom and reg_domain(retdom) != reg_f:
        chk("identity", "Return-Path differs from From", 8, True, f"Envelope sender @{retdom} vs From @{fdom}")
    else:
        chk("identity", "Return-Path differs from From", 0, False, "Consistent or absent")
    low = fname.lower()
    toks = [t for t in re.split(r"[^a-z0-9]+", low) if t]
    spoof = [b for b, offs in brands().items()
             if (b in toks or (len(b) >= 6 and b in low.replace(" ", ""))) and reg_f not in offs]
    if spoof:
        chk("identity", "Display name impersonates a brand", 25, True, f"Display name '{fname}' mentions {', '.join(spoof[:3])} but the address is @{fdom}")
    else:
        chk("identity", "Display name impersonates a brand", 0, False, "No brand name in the display name")
    roley = [w for w in ROLE_WORDS if w in low]
    if fdom in FREEMAIL and roley:
        chk("identity", "Free-mail sender posing as an official role", 10, True, f"'{fname}' ({roley[0]}) is sent from free provider {fdom}")
    else:
        chk("identity", "Free-mail sender posing as an official role", 0, False, "No role/brand claim from a free provider")
    long_dom = len(fdom) > 30 or fdom.count("-") >= 3
    chk("identity", "Unusually long / hyphenated sender domain", 8, long_dom, f"@{fdom} ({len(fdom)} chars, {fdom.count('-')} hyphens)")
    chk("identity", "Internationalised (xn--) sender domain", 10, "xn--" in fdom, f"@{fdom}")

    # ---- routing / message-id / date ----
    if not mid:
        chk("routing", "Message-ID missing", 8, True, "Legitimate mail servers always add a Message-ID")
    else:
        mism = bool(mdom) and reg_domain(mdom) != reg_f and fdom not in FREEMAIL
        chk("routing", "Message-ID domain differs from sender", 8, mism, f"Message-ID domain '{mdom}' vs sender '{fdom}'")
        chk("routing", "Overlong Message-ID domain", 6, len(mdom) > 35, f"'{mdom}' ({len(mdom)} chars)")
    chk("routing", "No Received headers", 6, hops == 0, f"{hops} Received hop(s)")
    chk("routing", "Very long relay chain", 3, hops > 10, f"{hops} Received hop(s)")
    undisclosed = (not to) or "undisclosed" in to.lower()
    chk("routing", "Recipient hidden / missing", 6, undisclosed, f"To: {to or 'N/A'}")
    try:
        dt = parsedate_to_datetime(date) if date else None
    except Exception:
        dt = None
    if dt is None:
        chk("routing", "Date missing or unparseable", 8, True, f"Date: {date or 'N/A'}")
    else:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        future = (dt - datetime.now(timezone.utc)).total_seconds() > 86400
        chk("routing", "Date is in the future", 6, future, f"Date: {date}")

    # ---- content cues ----
    hits = sorted({m.group(0).lower() for m in URGENT_RE.finditer(subj)})
    chk("content", "Urgency / pressure language in subject", 15 if len(hits) >= 2 else 10, bool(hits), f"Subject '{subj[:80]}' ({', '.join(hits[:4])})" if hits else "No pressure keywords")
    bulk = re.search(r"phpmailer|swiftmailer|massmail|sendblaster|bulk|mailer-daemon", xmailer, re.I)
    chk("content", "Bulk / script mailer fingerprint", 8, bool(bulk), f"X-Mailer: {xmailer or 'N/A'}")

    score = min(100, sum(c["points"] for c in checks))
    groups = {"auth": "Authentication", "identity": "Sender identity", "routing": "Message-ID & routing", "content": "Subject & content cues"}
    top = []
    for g, title in groups.items():
        gc = [c for c in checks if c["group"] == g]
        pts = sum(c["points"] for c in gc)
        lines = [f"{c['name']} (+{c['points']})" + f" - {c['evidence']}" for c in gc if c["hit"]]
        if g == "auth":
            lines = [f"SPF: {spf or 'n/a'}  ·  DKIM: {dkim or 'n/a'}  ·  DMARC: {dmarc or 'n/a'}"] + lines
        top.append(card(title, level_for_points(pts), lines or ["No anomalies found"]))
    fields = [
        {"k": "From", "v": frm or "N/A", "level": "yellow" if spoof else None},
        {"k": "To", "v": to or "N/A", "level": None},
        {"k": "Reply-To", "v": reply or "N/A", "level": "red" if rdom and reg_domain(rdom) != reg_f else None},
        {"k": "Delivered-To", "v": deliv or "N/A", "level": None},
        {"k": "Return-Path", "v": ret or "N/A", "level": None},
        {"k": "Subject", "v": subj or "N/A", "level": "yellow" if hits else None},
        {"k": "Date", "v": date or "N/A", "level": None},
        {"k": "Message-ID", "v": mid or "N/A", "level": None},
        {"k": "Message-ID Domain", "v": mdom or "N/A", "level": "yellow" if len(mdom) > 35 else None},
        {"k": "Received hops", "v": str(hops), "level": None},
        {"k": "Mailer", "v": xmailer or "N/A", "level": None},
        {"k": "Attachments", "v": f"{atts} file(s) detected", "level": None},
    ]
    drivers = sorted(({"label": c["name"], "points": c["points"]} for c in checks if c["hit"]), key=lambda d: -d["points"])
    details = [{"title": "Header fields", "rows": fields},
               {"title": "All header checks", "rows": [
                   {"k": c["name"], "v": (f"+{c['points']}  " if c["hit"] else "OK  ") + c["evidence"],
                    "level": level_for_points(c["points"]) if c["hit"] else "green"} for c in checks]}]
    z = zone_of(score)
    headline = {"green": "Headers look consistent", "yellow": "Header anomalies found - review", "red": "Header forgery / spoofing likely"}[z]
    return {"key": "header", "title": "Header Analysis", "score": score, "zone": z, "verdict": VERDICT_BY_ZONE[z],
            "headline": headline, "top": top, "details": details, "drivers": drivers,
            "_meta": {"from": frm, "subject": subj, "from_domain": fdom, "attachments": atts}}


# =====================================================================
#  D  -  DOMAIN ANALYSIS  (+ threat intelligence)
# =====================================================================
def legacy_domain_score(d: dict):
    """Fallback when neither the tool nor domain_risk_analyzer gave a risk_assessment."""
    lc, tls, pts, drv = d.get("lifecycle_and_attribution") or {}, d.get("cryptographic_tokens") or {}, 0, []
    age = lc.get("age_in_days")
    if age is not None:
        if age < 14:
            pts += 45; drv.append({"label": f"Domain only {age} days old", "points": 45})
        elif age < 30:
            pts += 30; drv.append({"label": f"Domain only {age} days old", "points": 30})
        elif age < 365:
            pts += 10; drv.append({"label": f"Domain under 1 year old ({age}d)", "points": 10})
    if tls and tls.get("ssl_active") is False:
        pts += 10; drv.append({"label": "No valid TLS certificate", "points": 10})
    return min(100, pts), drv


def intel_from_payload(payload: dict):
    rows, pts, drivers, lines = [], 0, [], []
    reports = (payload or {}).get("url_analyses") or {}
    if not reports and (payload or {}).get("url_enrichment"):
        reports = {(payload or {}).get("primary_analyzed_url") or "primary URL": payload["url_enrichment"]}
    for url, result in reports.items():
        verdict = str(result.get("verdict") or "INCONCLUSIVE").upper()
        risk = 85 if verdict == "MALICIOUS" else 45 if verdict == "SUSPICIOUS" else 0
        pts = max(pts, risk)
        rows.append({"k": f"URL {url[:75]}", "v": verdict, "level": "red" if risk >= 85 else "yellow" if risk else "na"})
        if risk:
            drivers.append({"label": f"URL reputation {verdict}: {url[:65]}", "points": risk})
        for provider, report in (result.get("raw_engine_reports") or {}).items():
            status = str(report.get("status") or "UNKNOWN").upper()
            detected = status == "MALICIOUS" or (provider == "virustotal" and (report.get("malicious") or 0) > 0) or (provider == "urlscan" and (report.get("historical_malicious_scans") or 0) > 0)
            rows.append({"k": provider, "v": f"{status} ({url[:65]})" + (f"; {report.get('malicious')} malicious detections" if provider == "virustotal" and report.get("malicious") is not None else ""),
                         "level": "red" if detected else "na" if status in ("ERROR", "SKIPPED", "UNAVAILABLE", "UNKNOWN", "NOT_FOUND", "NOT_LISTED") else "green"})
        lines.append(f"{url}: {verdict}")
    return pts, rows, drivers, lines


def _ind_rows(ra, who):
    rows = []
    for i in (ra or {}).get("indicators", []):
        tier = i["tier"]
        label = f"[{who}] T{tier} #{i['id']} {i['name']}" if tier != "S" else f"[{who}] {i['id']} {i['name']}"
        txt = (f"+{i['points']}  " if i["triggered"] else ("n/a  " if i.get("status") == "unavailable" else "OK  ")) + "; ".join(i["evidence"][:2])
        rows.append({"k": label, "v": txt, "level": ("red" if tier in (1, 2) else "yellow" if tier == 3 else "yellow") if i["triggered"] else ("na" if i.get("status") == "unavailable" else "green")})
    return rows


def analyze_domain_pillar(payload, from_dom, log):
    da = safe_get(payload or {}, "domain_analysis", default={}) or {}
    sender = da.get("sender_domain") or {}
    urld = da.get("body_url_domain") or {}
    mod = domain_mod()
    url = (payload or {}).get("primary_analyzed_url") or ""
    url_host = (urlparse(url).hostname or "") if url else (safe_get(payload or {}, "url_enrichment", "final_domain", default="") or "")

    def ensure(d, host, label):
        if isinstance(d, dict) and d.get("risk_assessment"):
            return d
        if mod is not None and host:
            try:
                if not Path(getattr(mod, "TRANCO_DB", "")).is_file():
                    log("info", "First run: downloading the Tranco top-1M list (one-time, ~20 MB) - this can take a moment ...")
                log("step", f"Scoring {label} domain {host} with domain_risk_analyzer ...")
                r = mod.analyze_full(host)
                if r.get("risk_assessment"):
                    orig = d if isinstance(d, dict) else {}
                    # keep the tool's own telemetry where the re-scan could not reach the network
                    if "error" in (r.get("lifecycle_and_attribution") or {}) and orig.get("lifecycle_and_attribution") and "error" not in orig["lifecycle_and_attribution"]:
                        r["lifecycle_and_attribution"] = orig["lifecycle_and_attribution"]
                    if not (r.get("infrastructure_and_hosting") or {}).get("resolved_ips") and (orig.get("infrastructure_and_hosting") or {}).get("resolved_ips"):
                        r["infrastructure_and_hosting"] = orig["infrastructure_and_hosting"]
                    if not (r.get("cryptographic_tokens") or {}).get("ssl_active") and (orig.get("cryptographic_tokens") or {}).get("ssl_active"):
                        r["cryptographic_tokens"] = orig["cryptographic_tokens"]
                    return r
            except BaseException as e:
                log("warn", f"domain_risk_analyzer failed for {host}: {type(e).__name__}")
        return d if isinstance(d, dict) else {}

    sender = ensure(sender, from_dom, "sender")
    urld = ensure(urld, url_host, "link") if url_host else urld

    def score_of(d):
        ra = d.get("risk_assessment")
        if ra:
            return ra["score"], ra.get("indicators", []), ra
        if d:
            s, drv = legacy_domain_score(d)
            return s, [], None
        return None, [], None


    s_score, s_ind, s_ra = score_of(sender)
    u_score, u_ind, u_ra = score_of(urld) if urld else (None, [], None)

    # URL intelligence from the email extraction pipeline
    i_score, i_rows, i_drv, i_lines = intel_from_payload(payload or {})

    # Preserve URL intelligence separately from domain intelligence.
    url_intel_available = any(
        row.get("level") not in (None, "na")
        for row in i_rows
    )

    domain_cti_scores = []
    domain_cti_verdicts = []

    for label, domain_result in (("Sender", sender), ("Link", urld)):
        if not isinstance(domain_result, dict) or not domain_result:
            continue

        ti = domain_result.get("threat_intelligence") or {}
        reports = ti.get("raw_engine_reports") or {}

        verdict = str(ti.get("verdict") or "INCONCLUSIVE").upper()
        domain_cti_verdicts.append(verdict)

        # Use the analyzer's correlated verdict once per domain.
        # Individual providers are evidence, not extra scores.
        if verdict == "MALICIOUS":
            risk = 90
            level = "red"
        elif verdict == "SUSPICIOUS":
            risk = 50
            level = "yellow"
        elif verdict == "NO_KNOWN_THREATS":
            risk = 0
            level = "green"
        else:
            risk = None
            level = "na"

        if risk is not None:
            domain_cti_scores.append(risk)

        i_rows.append({
            "k": f"{label} domain CTI",
            "v": verdict,
            "level": level,
        })

        i_lines.append(f"{label} domain reputation: {verdict}")

        if risk is not None and risk > 0:
            i_drv.append({
                "label": f"{label} domain intelligence: {verdict}",
                "points": risk,
            })

        # Display provider evidence without scoring it again.
        for provider, display_name in (
            ("virustotal", "VirusTotal"),
            ("mxtoolbox", "MXToolbox"),
            ("domainscan", "DomainScan"),
        ):
            report = reports.get(provider) or {}
            status = str(report.get("status") or "UNAVAILABLE").upper()

            if provider == "virustotal":
                malicious = int(report.get("malicious") or 0)
                suspicious = int(report.get("suspicious") or 0)
                evidence = (
                    f"{malicious} malicious, "
                    f"{suspicious} suspicious detections"
                )
                provider_level = (
                    "red" if malicious > 0
                    else "yellow" if suspicious > 0
                    else "green" if status == "OK"
                    else "na"
                )

            elif provider == "mxtoolbox":
                listings = report.get("listings") or []
                names = [
                    str(item.get("name") or "Unknown blacklist")
                    for item in listings
                    if isinstance(item, dict)
                ]
                listed_count = report.get("listed_count", len(names))

                evidence = f"{listed_count} blacklist listing(s)"
                if names:
                    evidence += ": " + ", ".join(names[:5])

                provider_level = (
                    "red" if status == "LISTED"
                    else "green" if status in ("OK", "NOT_LISTED")
                    else "na"
                )

            else:
                grade = str(
                    report.get("risk_grade") or "UNKNOWN"
                ).upper()

                evidence = (
                    f"Trust score: {report.get('trust_score', 'N/A')}; "
                    f"risk grade: {grade}; "
                    f"blacklist count: "
                    f"{report.get('blacklisted_count', 'N/A')}"
                )

                provider_level = (
                    "red" if grade in ("HIGH", "CRITICAL")
                    else "yellow" if grade in ("MEDIUM", "MODERATE")
                    else "green" if grade in ("LOW", "MINIMAL")
                    else "na"
                )

            if status in (
                "SKIPPED", "UNAVAILABLE", "ERROR", "INCONCLUSIVE"
            ):
                evidence = str(report.get("reason") or evidence)
                provider_level = "na"

            i_rows.append({
                "k": f"{label} · {display_name}",
                "v": f"{status} — {evidence}",
                "level": provider_level,
            })

            i_lines.append(
                f"{label} {display_name}: {status} — {evidence}"
            )

    # Use one CTI score per domain, not one per provider.
    # Do not count domain heuristics and domain CTI as
    # independent confirmations of malicious activity.
    heuristic_scores = [
        x for x in (s_score, u_score)
        if x is not None
    ]

    cands = heuristic_scores + domain_cti_scores

    if url_intel_available and i_score is not None:
        cands.append(i_score)

    if not cands:
        pillar = None
    else:
        pillar = max(cands)

        # Only apply the bonus when separate evidence categories
        # independently indicate elevated risk.
        heuristic_positive = any(x >= 30 for x in heuristic_scores)
        domain_cti_positive = any(
            x >= 50 for x in domain_cti_scores
        )
        url_cti_positive = (
            url_intel_available
            and i_score is not None
            and i_score >= 30
        )

        # Heuristic and reputation results for the same domain
        # can overlap. A bonus is reserved for independent
        # URL evidence alongside domain-level evidence.
        if url_cti_positive and (
            heuristic_positive or domain_cti_positive
        ):
            pillar = min(100, pillar + 10)

    have_intel = (
        url_intel_available
        or bool(domain_cti_scores)
    )


    # ---- the four summary cards ----
    def ages():
        out, lvl = [], "na"
        for lab, d in (("Sender domain", sender), ("Link domain", urld)):
            lc = (d or {}).get("lifecycle_and_attribution") or {}
            a = lc.get("age_in_days")
            if a is None:
                out.append(f"{lab}: unknown ({lc.get('error', 'no registry data')})")
            else:
                out.append(f"{lab}: {a} days old (created {lc.get('creation_date')})")
                l = "red" if a < 14 else "yellow" if a < 90 else "green"
                lvl = l if lvl in ("na", "green") or l == "red" else lvl
        return card("Domain Age", lvl, out)

    def typo():
        lines, lvl = [], "green"
        evaluated = False
        for lab, ra in (("Sender", s_ra), ("Link", u_ra)):
            if not ra:
                continue
            evaluated = True
            for i in ra.get("indicators", []):
                if i["id"] in (1, 2, 3, 5) and i["triggered"]:
                    lines.append(f"{lab}: {i['name']} (+{i['points']}) - {i['evidence'][0]}")
                    lvl = "red"
        if not evaluated:
            return card("Typosquatting / Look-alike", "na", ["Not evaluated - plug in domain_risk_analyzer.py for look-alike scoring"])
        return card("Typosquatting / Look-alike", lvl, lines or ["No look-alike, brand-stuffing or IDN patterns found"])

    def flux():
        lines, lvl = [], "na"
        for lab, d in (("Sender", sender), ("Link", urld)):
            inf = (d or {}).get("infrastructure_and_hosting") or {}
            ips, ttl = inf.get("resolved_ips") or [], inf.get("ttl_seconds")
            if ips and ttl is not None:
                ff = ttl <= 300 and len(ips) >= 3
                lines.append(f"{lab}: {len(ips)} IP(s), TTL {ttl}s" + (" - possible FAST-FLUX" if ff else ""))
                lvl = "red" if ff else ("green" if lvl == "na" else lvl)
        lines.append("Bulletproof-hosting check: not provided by the tool")
        return card("Fast-flux / Hosting", lvl, lines)

    top = [card("Threat Intelligence", "red" if i_score >= 50 else "yellow" if i_score >= 20 else ("green" if have_intel else "na"),
                i_lines or ["No threat-intel data in the tool output"]), ages(), typo(), flux()]

    details = []
    if s_ra:
        details.append({"title": f"Sender domain  {s_ra and sender.get('target_domain', from_dom)}  - score {s_score}/100 ({s_ra['risk_level']})",
                        "rows": _ind_rows(s_ra, "sender") + [{"k": "Recommendation", "v": s_ra.get("recommendation", ""), "level": None}]})
    elif s_score is not None:
        details.append({"title": f"Sender domain - legacy score {s_score}/100", "rows": [{"k": "Note", "v": "Fallback scoring (domain_risk_analyzer not available)", "level": "na"}]})
    if u_ra:
        details.append({"title": f"Link domain  {urld.get('target_domain', url_host)}  - score {u_score}/100 ({u_ra['risk_level']})", "rows": _ind_rows(u_ra, "link")})
    details.append({"title": "Threat intelligence engines", "rows": i_rows})
    drivers = []
    for ra, who in ((s_ra, "Sender"), (u_ra, "Link")):
        for i in (ra or {}).get("indicators", []):
            if i["triggered"]:
                drivers.append({"label": f"{who} domain: {i['name']}", "points": i["points"]})
    drivers += [{"label": d["label"], "points": d["points"]} for d in i_drv]
    drivers.sort(key=lambda d: -d["points"])
    z = zone_of(pillar)
    incomplete = any("error" in ((d or {}).get("lifecycle_and_attribution") or {}) for d in (sender, urld) if d)
    headline = {"green": "No domain red flags found" + (" (some registry lookups were unavailable)" if incomplete else ""),
                "yellow": "Some domain risk indicators - review",
                "red": "Domain infrastructure looks malicious", "na": "No domain data"}[z]
    return {"key": "domain", "title": "Domain Analysis", "score": pillar, "zone": z, "verdict": VERDICT_BY_ZONE[z],
            "headline": headline, "top": top, "details": details, "drivers": drivers,
            "_infra": [sender.get("infrastructure_and_hosting") or {}, urld.get("infrastructure_and_hosting") or {}]}


# =====================================================================
#  I  -  IP ANALYSIS
# =====================================================================
CLOUD_VPS = ("digitalocean", "linode", "akamai connected", "vultr", "choopa", "ovh", "hetzner", "contabo", "hostinger",
             "namecheap", "godaddy", "leaseweb", "scaleway", "oracle cloud", "alibaba", "tencent", "m247", "datacamp",
             "hostwinds", "interserver", "ionos", "hostgator", "bluehost", "microsoft azure", "google cloud", "amazon", "aws")
MAIL_PROVIDERS = ("google", "microsoft", "yahoo", "apple", "zoho", "proton", "fastmail", "mimecast", "proofpoint", "sendgrid", "mailchimp")


def analyze_ip_pillar(payload, domain_pillar):
    data = safe_get(payload or {}, "ip_analysis", "originating_ip_telemetry", default={}) or {}
    ip = data.get("query_ip") or str((payload or {}).get("originating_ip") or "").replace("[.]", ".")
    if not ip or ip == "Not Found":
        return {"key": "ip", "title": "IP Lookup", "score": None, "zone": "na", "verdict": "N/A", "headline": "No public origin IP identified", "top": [], "details": [], "drivers": []}
    network = data.get("network_intelligence") or {}
    rdap, asn, infra = network.get("rdap") or {}, network.get("asn") or {}, network.get("infrastructure") or {}
    ti = data.get("threat_intelligence") or {}
    risk = data.get("risk_assessment") or {}
    verdict = str(risk.get("verdict") or "INCONCLUSIVE").upper()
    score = 90 if verdict == "MALICIOUS" else 45 if verdict == "SUSPICIOUS" else 0 if verdict == "NO_KNOWN_THREATS" else None
    z = zone_of(score)
    rows = []
    for provider in ("virustotal", "abuseipdb", "spamhaus", "tor_exit"):
        r = ti.get(provider) or {}
        status = r.get("status", "NOT_QUERIED")
        fields = ", ".join(f"{k}={v}" for k, v in r.items() if k in ("malicious", "suspicious", "abuse_confidence_score", "total_reports", "is_tor_exit"))
        rows.append({"k": provider, "v": f"{status}" + (f"; {fields}" if fields else ""), "level": "red" if provider == "virustotal" and r.get("malicious", 0) > 0 or provider == "abuseipdb" and (r.get("abuse_confidence_score") or 0) >= 75 else "na"})
    rows.extend({"k": "Finding", "v": str(flag), "level": "yellow"} for flag in risk.get("triggered_flags") or [])
    top = [card("Origin IP", "na" if score is None else z, [ip, f"CTI: {verdict}"]),
           card("Network ownership", "na", [f"ASN: {asn.get('asn') or 'unknown'}", f"Organization: {asn.get('organization') or rdap.get('network_name') or 'unknown'}", f"Country: {rdap.get('country') or asn.get('country') or 'unknown'}"]),
           card("Cloud / CDN", "na", [str(infra.get('cloud_or_cdn_provider_hint') or 'not identified'), "Provider hints are not proof of shared tenancy"]),
           card("Reverse DNS", "na", [str((data.get('reverse_dns') or {}).get('ptr_hostname') or 'No PTR'), f"FCrDNS: {(data.get('reverse_dns') or {}).get('forward_confirmed')}"])]
    drivers = [{"label": str(flag), "points": score or 0} for flag in risk.get("triggered_flags") or []]
    return {"key": "ip", "title": "IP Lookup", "score": score, "zone": z, "verdict": VERDICT_BY_ZONE[z],
            "headline": f"IP reputation: {verdict}", "top": top, "details": [{"title": "Threat intelligence", "rows": rows}], "drivers": drivers,
            "_cti_verdict": verdict}


# =====================================================================
#  F  -  FILE ANALYSIS
# =====================================================================
RISKY_EXT = {".exe": 60, ".scr": 60, ".com": 55, ".pif": 55, ".js": 50, ".jse": 50, ".vbs": 55, ".vbe": 55, ".wsf": 55,
             ".bat": 50, ".cmd": 50, ".ps1": 55, ".lnk": 55, ".hta": 60, ".jar": 45, ".msi": 50, ".dll": 50, ".cpl": 50,
             ".xll": 55, ".chm": 40, ".reg": 40, ".iso": 45, ".img": 40, ".docm": 40, ".xlsm": 40, ".pptm": 40, ".xlam": 40,
             ".html": 35, ".htm": 35, ".shtml": 30, ".svg": 30, ".one": 25, ".ace": 25, ".rar": 20, ".7z": 20, ".zip": 15,
             ".doc": 15, ".xls": 15, ".rtf": 15, ".ppt": 10, ".gz": 10, ".tar": 10, ".pdf": 8}
DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip)\.(exe|scr|js|vbs|bat|cmd|lnk|com|hta|ps1)$", re.I)


def analyze_file_pillar(raw, payload):
    try:
        msg = message_from_bytes(raw, policy=policy.default)
    except Exception:
        msg = message_from_bytes(raw)
    items = []
    for part in msg.walk():
        try:
            fn = part.get_filename()
        except Exception:
            fn = None
        if not fn:
            continue
        data = part.get_payload(decode=True) or b""
        ext = os.path.splitext(fn.lower())[1]
        pts, ev = 0, []
        if ext in RISKY_EXT:
            pts = RISKY_EXT[ext]; ev.append(f"Extension {ext} is {'highly' if pts >= 45 else 'moderately' if pts >= 15 else 'slightly'} risky")
        if DOUBLE_EXT.search(fn):
            pts = max(pts, 45); ev.append("Double extension - disguised executable")
        if data[:2] == b"MZ" and ext not in (".exe", ".dll", ".scr", ".com", ".sys"):
            pts = max(pts, 55); ev.append("Windows executable content disguised as another file type")
        ctype = part.get_content_type()
        if ext == ".pdf" and "pdf" not in ctype and ctype != "application/octet-stream":
            pts += 10; ev.append(f"Declared type {ctype} does not match .pdf")
        items.append({"name": clean_text(fn, 120), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "ctype": ctype, "points": min(100, pts), "evidence": ev or ["No risky traits found"]})
    # merge whatever the tool reported (structure may vary)
    tool_items = (payload or {}).get("attachment_analysis") or []
    extra_rows, tool_pts = [], 0
    for t in tool_items:
        if not isinstance(t, dict):
            continue
        v = str(t.get("verdict") or t.get("alert_severity") or t.get("risk") or "").upper()
        p = 60 if v in ("MALICIOUS", "CRITICAL", "HIGH") else 30 if v in ("SUSPICIOUS", "MEDIUM") else 0
        tool_pts = max(tool_pts, p)
        extra_rows.append({"k": str(t.get("filename") or t.get("name") or "attachment"), "v": f"tool verdict: {v or 'n/a'}", "level": "red" if p >= 60 else "yellow" if p else "green"})
    if not items and not tool_items:
        return {"key": "file", "title": "File Analysis", "score": None, "zone": "na", "verdict": "NO ATTACHMENTS", "headline": "No attachments in this email",
                "top": [card("Attachments", "green", ["0 file(s) detected - nothing to scan"])], "details": [], "drivers": []}
    score = min(100, max([i["points"] for i in items] + [tool_pts]) + 5 * max(0, sum(1 for i in items if i["points"] >= 30) - 1))
    top = [card(i["name"], level_for_points(i["points"], 15, 40), [f"{i['size']:,} bytes · {i['ctype']}", f"SHA-256: {i['sha256'][:24]}..."] + i["evidence"]) for i in items[:4]]
    hash_lines = []
    for t in tool_items:
        if not isinstance(t, dict):
            continue
        hash_lines.append(f"{t.get('file_name') or 'attachment'}: {t.get('verdict') or t.get('error') or 'UNKNOWN'}")
        for provider, r in (t.get("raw_engine_reports") or {}).items():
            hash_lines.append(f"  {provider}: {r.get('status', 'UNKNOWN')}")
    top.append(card("Hash reputation", "red" if tool_pts >= 60 else "yellow" if tool_pts else "na", hash_lines or ["No hash intelligence available"]))
    rows = []
    for i in items:
        rows += [{"k": i["name"], "v": f"+{i['points']}  " + "; ".join(i["evidence"]), "level": level_for_points(i["points"], 15, 40)},
                 {"k": "  SHA-256", "v": i["sha256"], "level": None}, {"k": "  Size / type", "v": f"{i['size']:,} bytes · {i['ctype']}", "level": None}]
    details = [{"title": "Attachments", "rows": rows}] + ([{"title": "Analysis tool verdicts", "rows": extra_rows}] if extra_rows else [])
    drivers = sorted(({"label": f"Attachment {i['name']}", "points": i["points"]} for i in items if i["points"]), key=lambda d: -d["points"])
    z = zone_of(score)
    headline = {"green": "Attachments look benign", "yellow": "Attachment needs a careful look", "red": "Dangerous attachment type"}[z]
    return {"key": "file", "title": "File Analysis", "score": score, "zone": z, "verdict": VERDICT_BY_ZONE[z], "headline": headline,
            "top": top, "details": details, "drivers": drivers}


# =====================================================================
#  FINAL VERDICT + REPORT
# =====================================================================
def combine_final(pillars, payload):
    avail = {k: p for k, p in pillars.items() if p["score"] is not None}
    wsum = sum(WEIGHTS[k] for k in avail) or 1
    weighted = sum(p["score"] * WEIGHTS[k] for k, p in avail.items()) / wsum
    top_score = max([p["score"] for p in avail.values()] or [0])
    final = max(weighted, 0.85 * top_score)
    sev = str((payload or {}).get("alert_severity") or "").upper()
    floor = 0  # The extractor's legacy severity is not independent proof of maliciousness.
    confirmed = []
    for url, result in ((payload or {}).get("url_analyses") or {}).items():
        if result.get("verdict") == "MALICIOUS":
            confirmed.append(f"URL {url}")
    for key, result in ((payload or {}).get("domain_analysis") or {}).items():
        if (result.get("threat_intelligence") or {}).get("verdict") == "MALICIOUS":
            confirmed.append(f"Domain {key}")
    if safe_get(payload or {}, "ip_analysis", "originating_ip_telemetry", "risk_assessment", "verdict") == "MALICIOUS":
        confirmed.append("Origin IP")
    for result in (payload or {}).get("attachment_analysis") or []:
        if result.get("verdict") == "MALICIOUS":
            confirmed.append(f"Attachment {result.get('file_name', '')}")
    if confirmed:
        floor = 90
    final = int(round(min(100, max(final, floor))))
    z = zone_of(final)
    reasons = []
    for k, p in pillars.items():
        for d in p.get("drivers", [])[:3]:
            reasons.append({"label": f"{p['title']}: {d['label']}", "points": d["points"]})
    reasons.sort(key=lambda d: -d["points"])
    headline = {"green": "SAFE CATCH - nothing malicious detected", "yellow": "SUSPICIOUS - hold for manual review",
                "red": "PHISH CAUGHT - this email is very likely malicious"}[z]
    return {"score": final, "zone": z, "verdict": VERDICT_BY_ZONE[z], "headline": headline, "tool_severity": sev or "n/a",
            "reasons": reasons[:6], "confirmed_malicious_indicators": confirmed, "weights": WEIGHTS,
            "breakdown": [{"key": k, "title": p["title"], "score": p["score"], "zone": p["zone"], "weight": WEIGHTS[k]} for k, p in pillars.items()]}


def build_report(raw: bytes, payload, meta: dict, log):
    log("step", "Layer H - analysing headers ...")
    h = analyze_header(raw, payload)
    log("ok", f"Header score {h['score']}/100 ({h['verdict']})")
    log("step", "Layer D - domain & threat-intelligence analysis ...")
    d = analyze_domain_pillar(payload, h["_meta"]["from_domain"], log)
    log("ok", f"Domain score {d['score'] if d['score'] is not None else 'n/a'} ({d['verdict']})")
    log("step", "Layer I - IP lookup ...")
    i = analyze_ip_pillar(payload, d)
    log("ok", f"IP score {i['score'] if i['score'] is not None else 'n/a'} ({i['verdict']})")
    log("step", "Layer F - file analysis ...")
    f = analyze_file_pillar(raw, payload)
    log("ok", f"File score {f['score'] if f['score'] is not None else 'n/a'} ({f['verdict']})")
    pillars = {"header": h, "domain": d, "ip": i, "file": f}
    final = combine_final(pillars, payload)
    for p in pillars.values():
        p.pop("_meta", None); p.pop("_infra", None)
    return {"id": uuid.uuid4().hex, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "mode": meta.get("mode"),
            "file": {"name": meta.get("name"), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            "subject": h["details"][0]["rows"][5]["v"], "from": h["details"][0]["rows"][0]["v"],
            "pillars": pillars, "final": final,
            "notes": ["Scores are heuristic triage priorities, not probabilities or guarantees of safety.",
                      "Hash reputation is passive; a missing match does not prove safety.",
                      "Zones: green < %d, yellow < %d, red >= %d." % (ZONE_YELLOW, ZONE_RED, ZONE_RED)]}


def report_to_html(rep: dict) -> str:
    e = html.escape
    zc = {"green": "#1ee37a", "yellow": "#ffcc00", "red": "#b3202f", "na": "#6b7280"}
    out = [f"""<!doctype html><html><head><meta charset="utf-8"><title>Kingphisher-Man report</title><style>
body{{background:#05070a;color:#e8ffe8;font:14px/1.5 Consolas,monospace;max-width:980px;margin:24px auto;padding:0 16px}}
h1{{color:#ffb81c}}h2{{color:#1ee37a;border-bottom:1px solid #1ee37a55;padding-bottom:4px;margin-top:28px}}
.pill{{display:inline-block;padding:2px 10px;border-radius:4px;color:#fff;font-weight:bold}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}td{{border-bottom:1px solid #223;padding:4px 8px;vertical-align:top;word-break:break-word}}
td:first-child{{width:34%;color:#9fd}}.c{{border:1px solid #234;border-radius:6px;padding:8px;margin:6px 0}}</style></head><body>
<h1>THE KINGPHISHER-MAN - H·D·I·F Report</h1>
<p>Generated {e(rep['created'])} · mode {e(str(rep['mode']))}<br>File: {e(str(rep['file']['name']))} · {rep['file']['size']:,} bytes<br>SHA-256: {e(rep['file']['sha256'])}</p>"""]
    f = rep["final"]
    out.append(f"<h2>FINAL VERDICT</h2><p><span class='pill' style='background:{zc[f['zone']]}'>{e(f['verdict'])} · {f['score']}/100</span> {e(f['headline'])}<br>Tool correlated severity: {e(f['tool_severity'])}</p><table>")
    for b in f["breakdown"]:
        out.append(f"<tr><td>{e(b['title'])} (weight {b['weight']})</td><td>{'N/A' if b['score'] is None else str(b['score']) + '/100'} {e(VERDICT_BY_ZONE[b['zone']])}</td></tr>")
    out.append("</table><b>Top reasons</b><ul>" + "".join(f"<li>{e(r['label'])} (+{r['points']})</li>" for r in f["reasons"]) + "</ul>")
    for p in rep["pillars"].values():
        out.append(f"<h2>{e(p['title'])}  <span class='pill' style='background:{zc[p['zone']]}'>{'N/A' if p['score'] is None else str(p['score']) + '/100'} · {e(p['verdict'])}</span></h2><p>{e(p['headline'])}</p>")
        for c in p["top"]:
            out.append(f"<div class='c' style='border-color:{zc.get(c['level'], '#234')}'><b>{e(c['title'])}</b><br>" + "<br>".join(e(l) for l in c["lines"]) + "</div>")
        for s in p["details"]:
            out.append(f"<h3>{e(s['title'])}</h3><table>" + "".join(f"<tr><td>{e(str(r['k']))}</td><td>{e(str(r['v']))}</td></tr>" for r in s["rows"]) + "</table>")
    out.append("<h2>Notes</h2><ul>" + "".join(f"<li>{e(n)}</li>" for n in rep["notes"]) + "</ul></body></html>")
    return "".join(out)


# =====================================================================
#  QUOTA  (server-side, persistent, HMAC-signed)
# =====================================================================
class Quota:
    KINDS = ("demo", "upload", "pro")

    def __init__(self):
        for d in (DATA_DIR, UPLOAD_DIR, REPORT_DIR, LOG_DIR):
            d.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.tampered = False
        if SECRET_FILE.exists():
            self.secret = base64.b64decode(SECRET_FILE.read_text())
        else:
            self.secret = secrets.token_bytes(32)
            SECRET_FILE.write_text(base64.b64encode(self.secret).decode())
        self.counts = self._load() if QUOTA_ENABLED else self._fresh()   # ignore any old state file when disabled

    def _sig(self, counts):
        return hmac.new(self.secret, json.dumps(counts, sort_keys=True).encode(), hashlib.sha256).hexdigest()

    def _fresh(self):
        return {"demo": 0, "upload": 0, "pro": 0, "last_demo": None}

    def _load(self):
        if not STATE_FILE.exists():
            return self._fresh()
        try:
            d = json.loads(STATE_FILE.read_text())
            if not hmac.compare_digest(self._sig(d["counts"]), d["sig"]):
                raise ValueError("bad signature")
            return d["counts"]
        except Exception:
            self.tampered = True
            c = self._fresh()
            for k in self.KINDS:
                c[k] = LIMITS[k]               # locked until the owner runs --reset-quota
            return c

    def _save(self):
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"counts": self.counts, "sig": self._sig(self.counts)}))
        os.replace(tmp, STATE_FILE)

    def left(self, kind):
        if not QUOTA_ENABLED:
            return None                                  # None = unlimited
        lim = LIMITS[kind]
        return None if lim == 0 else max(0, lim - self.counts[kind])

    def consume(self, kind):
        if not QUOTA_ENABLED:
            return True                                  # never refuse a run
        with self.lock:
            lim = LIMITS[kind]
            if lim and self.counts[kind] >= lim:
                return False
            self.counts[kind] += 1
            self._save()
            return True

    def set_last_demo(self, rid):
        with self.lock:
            self.counts["last_demo"] = rid
            self._save()

    def snapshot(self):
        return {k: {"limit": LIMITS[k] if QUOTA_ENABLED else 0, "used": self.counts[k], "left": self.left(k)} for k in self.KINDS}

    def reset(self):
        with self.lock:
            self.counts = self._fresh()
            self.tampered = False
            self._save()


QUOTA = None


# =====================================================================
#  JOBS
# =====================================================================
class Job:
    def __init__(self, kind):
        self.id = uuid.uuid4().hex
        self.kind = kind
        self.status = "running"
        self.events = []
        self.report_id = None
        self.error = None
        self.countdown = None
        self.proc = None
        self.secrets = []
        self.created = time.time()


JOBS = {}
RUN_LOCK = threading.Lock()
LAST_START = [0.0]


def emit(job, tag, msg, stage=None, **kw):
    ev = {"i": len(job.events), "t": time.strftime("%H:%M:%S"), "tag": tag,
          "msg": redact(clean_text(msg), job.secrets), "stage": stage}
    ev.update(kw)
    job.events.append(ev)


def save_report(rep):
    (REPORT_DIR / f"{rep['id']}.json").write_text(json.dumps(rep, ensure_ascii=False), encoding="utf-8")


def load_report(rid):
    if not re.fullmatch(r"[0-9a-f]{32}", rid or ""):
        return None
    p = REPORT_DIR / f"{rid}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None


def finish_with_report(job, raw, payload, meta, stored_name, stage_final):
    emit(job, "step", "Building the H·D·I·F report ...", stage=stage_final)
    rep = build_report(raw, payload, meta, lambda t, m: emit(job, t, m, stage=stage_final))
    rep["stored_as"] = stored_name
    save_report(rep)
    job.report_id = rep["id"]
    return rep


def job_guard(job, fn, *a):
    try:
        fn(job, *a)
        if job.status == "running":
            job.status = "done"
    except ToolError as e:
        job.status, job.error = "error", str(e)
        emit(job, "fail", str(e))
    except Exception as e:                                      # never leak internals to the client
        say(R, "job", f"{type(e).__name__}: {e}")
        job.status, job.error = "error", f"Internal error ({type(e).__name__}) - see the server console"
        emit(job, "fail", job.error)
    finally:
        RUN_LOCK.release()


# ---- A: ROOKIE demo -------------------------------------------------
def gh_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "kingphisher-ui", "Accept": "application/vnd.github+json",
                                               **({"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(8 * 1024 * 1024)


def used_samples():
    names = set()
    if REPO_COUNTER_LOG.exists():
        for line in REPO_COUNTER_LOG.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.split("|")[0].strip():
                names.add(line.split("|")[0].strip())
    return names


def run_demo(job):
    emit(job, "step", "Casting the line - listing phishing_pot samples ...", stage=1)
    try:
        tree = json.loads(gh_get(f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{REPO_BRANCH}:{REPO_DIR}"))
    except Exception as e:
        raise ToolError(f"Could not reach GitHub ({type(e).__name__}). Check your internet connection.")
    names = [t["path"] for t in tree["tree"] if t["type"] == "blob" and t["path"].lower().endswith(".eml") and re.fullmatch(r"[\w\-. ]+\.eml", t["path"])]
    pool = [n for n in names if n not in used_samples()]
    emit(job, "ok", f"{len(names)} samples in the pond, {len(pool)} not yet caught", stage=1)
    if not pool:                                   # every sample was caught before -> reuse one, never stop
        pool = names
        emit(job, "info", "Every sample has been caught before - fishing one out again", stage=1)
    if not pool:
        raise ToolError("The repository returned no .eml samples")
    name = random.choice(pool)
    emit(job, "step", f"Hooking {name} ...", stage=2)
    try:
        raw = gh_get(f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{REPO_BRANCH}/{REPO_DIR}/{name}")
    except Exception as e:
        raise ToolError(f"Download failed ({type(e).__name__})")
    stored = f"{uuid.uuid4().hex}.eml"
    (UPLOAD_DIR / stored).write_bytes(raw)
    emit(job, "ok", f"Caught {name} ({len(raw):,} bytes)", stage=2)
    emit(job, "step", "Logging the catch so it is never fetched again ...", stage=3)
    with open(REPO_COUNTER_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{name} | FETCHED_BY_UI | {datetime.now():%Y-%m-%d %H:%M:%S}\n")
    emit(job, "ok", "Recorded in repo_eml_counter.log", stage=3)
    if not QUOTA.consume("demo"):
        raise ToolError("The demo has already been used")
    emit(job, "step", "Running the analysis tool (headers, domains, IPs, files) ...", stage=4)
    payload = run_tool(UPLOAD_DIR / stored)
    emit(job, "ok", "Tool finished", stage=4)
    rep = finish_with_report(job, raw, payload, {"mode": "demo", "name": name}, stored, 5)
    QUOTA.set_last_demo(rep["id"])
    emit(job, "ok", "Delivery to your inbox is skipped in the UI demo (use Section 1 for that)", stage=5)
    emit(job, "ok", f"Final verdict: {rep['final']['verdict']} ({rep['final']['score']}/100)", stage=5)


# ---- B: AMATEUR upload ---------------------------------------------
def run_upload(job, stored, name, rerun_of=None):
    p = UPLOAD_DIR / stored
    raw = p.read_bytes()
    emit(job, "ok", f"Received {name} ({len(raw):,} bytes)", stage=1)
    emit(job, "ok", "Looks like a valid email file", stage=2)
    if not QUOTA.consume("upload"):
        raise ToolError("No analysis runs left")
    emit(job, "step", "Running the analysis tool ...", stage=3)
    payload = run_tool(p)
    emit(job, "ok", "Tool finished", stage=3)
    rep = finish_with_report(job, raw, payload, {"mode": "upload", "name": name}, stored, 4)
    emit(job, "ok", f"Final verdict: {rep['final']['verdict']} ({rep['final']['score']}/100)", stage=4)


# ---- C: PRO live guard ---------------------------------------------
STAGE_RE = re.compile(r"PHASE (\d)/5")
SAVED_RE = re.compile(r"Saved (\S+\.eml)")
COUNT_RE = re.compile(r"(\d\d):(\d\d) left")


def run_pro(job, target, password, sender):
    env = dict(os.environ, GMAIL_APP_PASSWORD=password, SOC_TARGET_EMAIL=target, SOC_TOOL_SCRIPT=TOOL_SCRIPT,
               PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    job.secrets = [password, password.replace(" ", "")]
    cmd = [sys.executable, str(GUARD_SCRIPT), "--sender", sender, "--timeout", str(PRO_WAIT_SECONDS), "--hide-tool-output"]
    emit(job, "step", f"Starting the live guard for {target} ...", stage=1)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace", env=env, cwd=str(GUARD_SCRIPT.parent), bufsize=1)
    password = None
    job.proc = proc
    saved, consumed, no_mail = None, False, False
    for line in proc.stdout:
        line = clean_text(line.replace("\r", " "), 400).strip()
        if not line:
            continue
        m = COUNT_RE.search(line)
        if "Listening for mail" in line and m:
            job.countdown = int(m.group(1)) * 60 + int(m.group(2))
            continue
        if "TARGET MAIL DETECTED" in line and not consumed:
            consumed = True
            if not QUOTA.consume("pro"):
                proc.terminate()
                raise ToolError("No PRO guard runs left")
        sm = STAGE_RE.search(line)
        if sm:
            emit(job, "stage", f"Phase {sm.group(1)}/5", stage=int(sm.group(1)))
            continue
        if "No new mail from" in line:
            no_mail = True
        sv = SAVED_RE.search(line)
        if sv and re.fullmatch(r"[0-9A-Za-z_.\-]+\.eml", sv.group(1)):
            saved = sv.group(1)
        tag = "ok" if "[ OK ]" in line else "warn" if "[WARN]" in line else "fail" if "[FAIL]" in line else "step" if "[STEP]" in line else "info"
        if any(t in line for t in ("[ OK ]", "[WARN]", "[FAIL]", "[STEP]", "[INFO]", "DETECTED", "From", "Subject", "VERDICT")):
            emit(job, tag, re.sub(r"^\[[0-9\- :]+\]\s*\[\s*\w+\s*\]\s*", "", line))
    proc.wait()
    job.countdown = None
    held = GUARD_SCRIPT.parent / "eml_held"
    if saved and (held / saved).is_file():
        raw = (held / saved).read_bytes()
        aj = held / (saved + ".analysis.json")
        payload = None
        if aj.is_file():
            try:
                payload = json.loads(aj.read_text(encoding="utf-8"))
            except ValueError:
                payload = None
        if payload is None:
            emit(job, "warn", "The guard did not leave an analysis file - running the tool again", stage=4)
            payload = run_tool(held / saved)
        stored = f"{uuid.uuid4().hex}.eml"
        (UPLOAD_DIR / stored).write_bytes(raw)
        rep = finish_with_report(job, raw, payload, {"mode": "pro", "name": saved}, stored, 5)
        emit(job, "ok", f"Final verdict: {rep['final']['verdict']} ({rep['final']['score']}/100)", stage=5)
    elif no_mail:
        job.status = "timeout"
        emit(job, "warn", f"No new mail found within {PRO_WAIT_SECONDS // 60} minutes - the guard stopped.")
    elif job.status == "running":
        raise ToolError("The guard stopped without analysing a mail - check the credentials and that IMAP is enabled in Gmail")


# =====================================================================
#  HTTP SERVER
# =====================================================================
CSRF = secrets.token_urlsafe(24)
ALLOWED_HOSTS = set()
STATIC = {"/ui/app.css": (UI_DIR / "app.css", "text/css; charset=utf-8"),
          "/ui/app.js": (UI_DIR / "app.js", "application/javascript; charset=utf-8"),
          "/ui/intro.js": (UI_DIR / "intro.js", "application/javascript; charset=utf-8"),
          "/assets/Kingfisher-Man.png": (ASSET_DIR / "Kingfisher-Man.png", "image/png")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
       "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$")


class Handler(BaseHTTPRequestHandler):
    server_version = "KingPhisher"
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    # ---- helpers ----
    def _send(self, code, body: bytes, ctype, extra=None, csp=CSP):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _err(self, code, msg, **kw):
        self._json(code, {"error": msg, **kw})

    def _gate(self, post=False):
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            self._err(403, "Bad host")
            return False
        if post:
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{h}" for h in ALLOWED_HOSTS}:
                self._err(403, "Bad origin")
                return False
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), CSRF):
                self._err(403, "Bad token - reload the page")
                return False
        return True

    def _body(self, limit):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if n < 0 or n > limit:
            self._err(413, f"Body too large (max {limit // 1024} KB)")
            return None
        return self.rfile.read(n)

    # ---- GET ----
    def do_GET(self):
        if not self._gate():
            return
        u = urlparse(self.path)
        path = u.path
        if path == "/":
            html_ = (UI_DIR / "index.html").read_text(encoding="utf-8").replace("__CSRF__", CSRF)
            return self._send(200, html_.encode("utf-8"), "text/html; charset=utf-8")
        if path in STATIC:
            f, ctype = STATIC[path]
            if not f.is_file():
                return self._err(404, "Missing file: " + f.name)
            return self._send(200, f.read_bytes(), ctype)
        if path == "/api/status":
            return self._json(200, {"quota": QUOTA.snapshot(), "tampered": QUOTA.tampered, "busy": RUN_LOCK.locked(),
                                    "tool_ok": Path(TOOL_SCRIPT).is_file(), "guard_ok": GUARD_SCRIPT.is_file(),
                                    "domain_tool_ok": DOMAIN_ANALYZER.is_file(), "pro_wait": PRO_WAIT_SECONDS,
                                    "last_demo": QUOTA.counts.get("last_demo")})
        m = re.fullmatch(r"/api/job/([0-9a-f]{32})", path)
        if m:
            job = JOBS.get(m.group(1))
            if not job:
                return self._err(404, "Unknown job")
            try:
                since = max(0, int(parse_qs(u.query).get("since", ["0"])[0]))
            except ValueError:
                since = 0
            return self._json(200, {"status": job.status, "events": job.events[since:], "report": job.report_id,
                                    "error": job.error, "countdown": job.countdown, "kind": job.kind, "quota": QUOTA.snapshot()})
        m = re.fullmatch(r"/api/report/([0-9a-f]{32})(\.json|\.html)?", path)
        if m:
            rep = load_report(m.group(1))
            if not rep:
                return self._err(404, "Unknown report")
            ext = m.group(2)
            if ext == ".html":
                return self._send(200, report_to_html(rep).encode("utf-8"), "text/html; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="KingPhisher_Report_{rep["id"][:8]}.html"'},
                                  csp="default-src 'none'; style-src 'unsafe-inline'; sandbox")
            if ext == ".json":
                return self._send(200, json.dumps(rep, indent=2, ensure_ascii=False).encode("utf-8"), "application/json",
                                  {"Content-Disposition": f'attachment; filename="KingPhisher_Report_{rep["id"][:8]}.json"'})
            return self._json(200, rep)
        self._err(404, "Not found")

    # ---- POST ----
    def _start(self, kind, target, *args):
        now = time.time()
        if now - LAST_START[0] < COOLDOWN_SECONDS:
            return self._err(429, "Slow down - wait a few seconds")
        if not RUN_LOCK.acquire(blocking=False):
            return self._err(409, "Another analysis is already running")
        LAST_START[0] = now
        job = Job(kind)
        JOBS[job.id] = job
        for old in [k for k, j in JOBS.items() if now - j.created > 3600 and k != job.id]:
            JOBS.pop(old, None)
        threading.Thread(target=job_guard, args=(job, target) + args, daemon=True).start()
        self._json(200, {"job": job.id})

    def do_POST(self):
        if not self._gate(post=True):
            return
        path = urlparse(self.path).path
        if path == "/api/demo/start":
            if QUOTA.left("demo") == 0:
                return self._err(403, "The demo can only be run once.", last_demo=QUOTA.counts.get("last_demo"))
            return self._start("demo", run_demo)

        if path == "/api/upload/start":
            if QUOTA.left("upload") == 0:
                return self._err(403, "No analysis runs left.")
            data = self._body(MAX_UPLOAD_BYTES)
            if data is None:
                return
            name = re.sub(r"[^\w.\- ]", "_", os.path.basename(unquote(self.headers.get("X-Filename", "upload.eml"))))[:80] or "upload.eml"
            if not name.lower().endswith(".eml"):
                return self._err(400, "Only .eml files are accepted")
            if not data or b"\x00" in data[:2048]:
                return self._err(400, "That does not look like an email file")
            try:
                m = message_from_bytes(data)
            except Exception:
                return self._err(400, "That does not look like an email file")
            if sum(1 for h in ("from", "to", "subject", "date", "received", "message-id") if m.get(h)) < 2:
                return self._err(400, "No email headers found in that file")
            stored = f"{uuid.uuid4().hex}.eml"
            (UPLOAD_DIR / stored).write_bytes(data)
            return self._start("upload", run_upload, stored, name)

        m = re.fullmatch(r"/api/rerun/([0-9a-f]{32})", path)
        if m:
            rep = load_report(m.group(1))
            if not rep or rep.get("mode") == "demo" or not rep.get("stored_as") or not (UPLOAD_DIR / rep["stored_as"]).is_file():
                return self._err(404, "This result cannot be re-run")
            if QUOTA.left("upload") == 0:
                return self._err(403, "No analysis runs left.")
            return self._start("upload", run_upload, rep["stored_as"], rep["file"]["name"])

        if path == "/api/pro/start":
            if QUOTA.left("pro") == 0:
                return self._err(403, "No PRO guard runs left.")
            body = self._body(8192)
            if body is None:
                return
            try:
                d = json.loads(body)
                target, pw, sender = str(d["target"]).strip(), str(d["password"]), str(d["sender"]).strip()
            except Exception:
                return self._err(400, "Bad request")
            pw_clean = pw.replace(" ", "")
            if not EMAIL_RE.match(target) or not target.lower().endswith(("@gmail.com", "@googlemail.com")):
                return self._err(400, "Enter the Gmail address of the inbox to guard")
            if not EMAIL_RE.match(sender):
                return self._err(400, "Enter the sender address whose mail should be analysed")
            if not re.fullmatch(r"[A-Za-z0-9]{16}", pw_clean):
                return self._err(400, "A Gmail App Password has 16 letters/digits")
            if not GUARD_SCRIPT.is_file():
                return self._err(500, "section2_live_guard.py not found next to this file")
            return self._start("pro", run_pro, target, pw, sender)

        m = re.fullmatch(r"/api/job/([0-9a-f]{32})/stop", path)
        if m:
            job = JOBS.get(m.group(1))
            if job and job.proc and job.status == "running":
                job.status = "stopped"
                emit(job, "warn", "Stopped by user")
                try:
                    job.proc.terminate()
                except Exception:
                    pass
            return self._json(200, {"ok": True})
        self._err(404, "Not found")


def check_setup():
    ok = True
    for label, p, need in (("Analysis tool (TOOL_SCRIPT)", Path(TOOL_SCRIPT), True), ("Live guard (section2_live_guard.py)", GUARD_SCRIPT, False),
                           ("Domain analyzer (domain_risk_analyzer.py)", DOMAIN_ANALYZER, False), ("UI files", UI_DIR / "app.js", True),
                           ("Logo", ASSET_DIR / "Kingfisher-Man.png", False)):
        found = p.is_file()
        say(G if found else (R if need else Y), "check", f"{'FOUND  ' if found else 'MISSING'} {label}: {p}")
        ok &= found or not need
    m = domain_mod()
    say(G if m else Y, "check", "domain_risk_analyzer importable" if m else "domain_risk_analyzer NOT importable (fallback scoring will be used; run: pip install requests dnspython cryptography tldextract rapidfuzz)")
    return ok


def main():
    global QUOTA
    ap = argparse.ArgumentParser(description="The Kingphisher-Man UI")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--reset-quota", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    show_startup_banner()
    QUOTA = Quota()
    if a.reset_quota:
        QUOTA.reset()
        say(G, "quota", "Usage counters reset.")
        return
    say(B, "ui", "THE KINGPHISHER-MAN  -  starting ...")
    ok = check_setup()
    if a.check:
        return
    srv = None
    for port in range(a.port, a.port + 10):
        try:
            srv = ThreadingHTTPServer((HOST, port), Handler)
            break
        except OSError:
            continue
    if srv is None:
        say(R, "ui", "No free port found")
        sys.exit(1)
    srv.daemon_threads = True
    port = srv.server_address[1]
    ALLOWED_HOSTS.update({f"127.0.0.1:{port}", f"localhost:{port}"})
    if not QUOTA_ENABLED:
        say(G, "quota", "DISABLED - Rookie, Amateur and Pro can be run any number of times")
    else:
        if QUOTA.tampered:
            say(R, "quota", "State file signature invalid - runs are LOCKED. Owner: run  python kingphisher_ui.py --reset-quota")
        snap = QUOTA.snapshot()
        say(W, "quota", "  ".join(f"{k}: {v['left'] if v['left'] is not None else '∞'} left" for k, v in snap.items()))
    url = f"http://127.0.0.1:{port}/"
    say(G, "ui", f"Open {url}   (Ctrl+C to quit)")
    if not a.no_browser:
        threading.Thread(
            target=browser_countdown,
            args=(url, 5),
            daemon=True
        ).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for j in JOBS.values():
            if j.proc and j.proc.poll() is None:
                j.proc.terminate()
        srv.server_close()


if __name__ == "__main__":
    main()
