#!/usr/bin/env python3
"""
Phishing SOC Simulator - SECTION 1
phishing_pot (GitHub) -> analysis tool -> verdict -> Gmail (Inbox or Spam)

Requires:  pip install requests          (optional: pip install pyyaml  -> YAML tool output)

Usage:
  python section1_delivery.py                      # defaults from config below
  python section1_delivery.py --direct             # skip the tool, deliver straight to inbox
  python section1_delivery.py --analyze            # run the tool, then deliver by verdict
  python section1_delivery.py --show-tool-output   # stream the tool's terminal output live
  python section1_delivery.py --hide-tool-output   # run the tool silently
  python section1_delivery.py -n 3                 # number of samples this run
"""

import os
import re
import sys
import json
import html
import random
import smtplib
import imaplib
import argparse
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

import requests

# =====================================================================
#  CONFIGURATION  (edit this block)
# =====================================================================
GMAIL_USER = "Enter your GMAIL USER HERE" #Enter your Gmail address (e.g. "yourname@gmail.com")

# >>> PUT YOUR GOOGLE APP PASSWORD HERE <<<  (16 chars, spaces are fine)
# Safer: set env var once ->  setx GMAIL_APP_PASSWORD "abcd efgh ijkl mnop"  (reopen terminal)
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "Enter your GMAIL APP PASSWORD HERE")

SMTP_MODE = "STARTTLS"          # "STARTTLS" (587)  or  "SSL" (465)
SMTP_HOST = "smtp.gmail.com"
IMAP_HOST = "imap.gmail.com"    # used to place quarantined mail in Spam/Trash (enable IMAP in Gmail settings)

# ---- Pipeline mode -------------------------------------------------
DELIVERY_MODE = "ANALYZE"       # "DIRECT" = no tool, straight to inbox | "ANALYZE" = tool -> verdict -> deliver
SHOW_TOOL_OUTPUT = True         # True = stream the tool's terminal output live | False = run silently

NUM_EMAILS = 5
DELAY_BETWEEN_SENDS = 3         # seconds
TOOL_TIMEOUT = 300              # seconds per email

# ---- Your analysis tool -------------------------------------------
TOOL_SCRIPT = r"C:\Users\risha\Desktop\CV related Documents\SOC Home Lab\Architecture & Notes\email_data_extractor1.1.py"

# ---- Verdict logic -------------------------------------------------
# The tool's correlated verdict ("alert_severity") is the REAL verdict.
# Edit this map if your tool uses other labels. Unknown labels => "suspicious" (fail-safe).
SEVERITY_TO_VERDICT = {
    "CRITICAL": "malicious",
    "HIGH": "malicious",
    "MEDIUM": "suspicious",
    "LOW": "safe",
    "INFO": "safe",
    "INFORMATIONAL": "safe",
    "NONE": "safe",
    "CLEAN": "safe",
    "SAFE": "safe",
}
# Where non-safe mail goes (IMAP folder names). Use "[Gmail]/Trash" if you prefer Trash.
QUARANTINE_FOLDER = {
    "malicious": "[Gmail]/Spam",
    "suspicious": "[Gmail]/Spam",
}

# ---- GitHub source -------------------------------------------------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")   # optional, raises API rate limit
REPO_OWNER, REPO_NAME, REPO_BRANCH, REPO_DIR = "rf-peixoto", "phishing_pot", "main", "email"

# ---- Paths ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
EML_DIR = BASE_DIR / "eml_samples"

LOG_REPO_COUNTER = LOG_DIR / "repo_eml_counter.log"   # every eml ever fetched (never re-fetched)
LOG_CUR_TMP = LOG_DIR / "cur_tmp_eml.log"             # delivered / queued, verdict pending
LOG_FINAL = LOG_DIR / "final_repo_eml.log"            # name | verdict | severity | destination

# =====================================================================
#  TERMINAL COLORS / OUTPUT
# =====================================================================
os.system("")  # enable ANSI colors on Windows cmd / PowerShell
W, G, B, Y, R, X = "\033[97m", "\033[92m", "\033[94m", "\033[93m", "\033[91m", "\033[0m"
GRAY, BOLD = "\033[90m", "\033[1m"
_print_lock = threading.Lock()


def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _out(s):
    with _print_lock:
        sys.stdout.write(s + "\n")
        sys.stdout.flush()


def info(m):  _out(f"{W}[{ts()}] [INFO]   {m}{X}")
def ok(m):    _out(f"{G}[{ts()}] [ OK ]   {m}{X}")
def step(m):  _out(f"{B}[{ts()}] [STEP]   {m}{X}")
def warn(m):  _out(f"{Y}[{ts()}] [WARN]   {m}{X}")
def err(m):   _out(f"{R}[{ts()}] [FAIL]   {m}{X}")


def banner():
    _out(f"{B}{BOLD}")
    _out("  ╔══════════════════════════════════════════════════════╗")
    _out("  ║     The KingPhisher-Man is Phishing for Phishes      ║")
    _out("  ║            $ ./Terminal Based Version                ║")
    _out("  ╚══════════════════════════════════════════════════════╝")
    _out(X)


# =====================================================================
#  LOG HELPERS
# =====================================================================
def init_logs():
    LOG_DIR.mkdir(exist_ok=True)
    EML_DIR.mkdir(exist_ok=True)
    for f in (LOG_REPO_COUNTER, LOG_CUR_TMP, LOG_FINAL):
        f.touch(exist_ok=True)


def read_names(logfile):
    names = set()
    for line in logfile.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = line.split("|")
        if parts and parts[0].strip():
            names.add(parts[0].strip())
    return names


def append_log(logfile, *cols):
    with open(logfile, "a", encoding="utf-8") as fh:
        fh.write(" | ".join([str(c) for c in cols] + [ts()]) + "\n")


def remove_from_log(logfile, name):
    lines = logfile.read_text(encoding="utf-8", errors="ignore").splitlines()
    kept = [l for l in lines if l.split("|")[0].strip() != name]
    logfile.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")


# =====================================================================
#  GITHUB FETCH
# =====================================================================
def gh_headers():
    h = {"Accept": "application/vnd.github+json", "User-Agent": "phishing-soc-sim"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def list_repo_emls():
    """Git Trees API (the Contents API caps at 1000 files)."""
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{REPO_BRANCH}:{REPO_DIR}"
    r = requests.get(url, headers=gh_headers(), timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("truncated"):
        warn("GitHub tree listing was truncated; some files may be unreachable.")
    return [t["path"] for t in data["tree"] if t["type"] == "blob" and t["path"].lower().endswith(".eml")]


def download_eml(name):
    url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{REPO_BRANCH}/{REPO_DIR}/{name}"
    r = requests.get(url, headers={"User-Agent": "phishing-soc-sim"}, timeout=60)
    r.raise_for_status()
    return r.content


def pick_new_emls(n):
    step("Querying GitHub API for sample list ...")
    all_files = list_repo_emls()
    info(f"Repository contains {len(all_files)} .eml files")
    used = read_names(LOG_REPO_COUNTER)
    pool = [f for f in all_files if f not in used]
    info(f"{len(used)} already used (skipped) | {len(pool)} still available")
    if not pool:
        warn("No unused samples left in repository.")
        return []
    return random.sample(pool, min(n, len(pool)))


# =====================================================================
#  DELIVERY
# =====================================================================
def normalize_crlf(raw: bytes) -> bytes:
    return re.sub(rb"\r?\n", b"\r\n", raw)


def smtp_connect():
    pwd = GMAIL_APP_PASSWORD.replace(" ", "")
    if SMTP_MODE.upper() == "SSL":
        s = smtplib.SMTP_SSL(SMTP_HOST, 465, timeout=60)
    else:
        s = smtplib.SMTP(SMTP_HOST, 587, timeout=60)
        s.ehlo()
        s.starttls()
        s.ehlo()
    s.login(GMAIL_USER, pwd)
    return s


def deliver_raw_smtp(raw: bytes):
    """Message bytes sent as-is: inner To:/From:/Subject: are not touched. Envelope recipient = your Gmail."""
    s = smtp_connect()
    try:
        s.sendmail(GMAIL_USER, [GMAIL_USER], normalize_crlf(raw))
    finally:
        try:
            s.quit()
        except Exception:
            pass


def deliver_to_folder_imap(raw: bytes, folder: str):
    """IMAP APPEND straight into [Gmail]/Spam or [Gmail]/Trash (SMTP cannot target folders)."""
    m = imaplib.IMAP4_SSL(IMAP_HOST)
    try:
        m.login(GMAIL_USER, GMAIL_APP_PASSWORD.replace(" ", ""))
        typ, data = m.append(f'"{folder}"', None, imaplib.Time2Internaldate(time.time()), normalize_crlf(raw))
        if typ != "OK":
            raise RuntimeError(f"IMAP APPEND to {folder} failed: {typ} {data}")
    finally:
        try:
            m.logout()
        except Exception:
            pass


# =====================================================================
#  ANALYSIS TOOL RUNNER
# =====================================================================
def _pump(stream, bucket, show, color):
    for line in iter(stream.readline, ""):
        bucket.append(line)
        if show:
            _out(f"{color}  │ {line.rstrip()}{X}")
    stream.close()


def run_tool_process(tool: Path, eml_path: Path, show: bool):
    """Runs the tool, captures stdout/stderr, optionally streams them live. Returns (rc, stdout, stderr)."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, str(tool), str(eml_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        cwd=str(tool.parent), env=env, bufsize=1,
    )
    out_lines, err_lines = [], []
    t1 = threading.Thread(target=_pump, args=(proc.stdout, out_lines, show, GRAY), daemon=True)
    t2 = threading.Thread(target=_pump, args=(proc.stderr, err_lines, show, Y), daemon=True)

    if show:
        _out(f"{GRAY}  ┌──────────── tool output: {tool.name} ────────────{X}")
    t1.start(); t2.start()
    try:
        proc.wait(timeout=TOOL_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError(f"Tool timed out after {TOOL_TIMEOUT}s")
    finally:
        t1.join(5); t2.join(5)
        if show:
            _out(f"{GRAY}  └──────────── end of tool output ────────────{X}")
    return proc.returncode, "".join(out_lines), "".join(err_lines)


def extract_payload(text: str) -> dict:
    """
    Pulls the alert payload out of the tool's stdout. Handles:
      * a header line followed by pretty-printed multi-line JSON (your tool)
      * compact single-line JSON
      * YAML (needs: pip install pyyaml)
    """
    text = text.strip()
    if not text:
        raise ValueError("Tool produced no output on stdout")

    # 1) whole output is JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass

    # 2) JSON object starting at column 0 of some line (skips header/log lines)
    dec = json.JSONDecoder()
    best, best_len = None, 0
    for m in re.finditer(r"(?m)^\{", text):
        try:
            obj, end = dec.raw_decode(text[m.start():])
        except ValueError:
            continue
        if isinstance(obj, dict) and end > best_len:
            best, best_len = obj, end
    if best is not None:
        return best

    # 3) YAML fallback (drop "[ header ]" style lines first)
    try:
        import yaml
        cleaned = "\n".join(l for l in text.splitlines() if not re.match(r"^\s*\[.*\]\s*$", l))
        obj = yaml.safe_load(cleaned)
        if isinstance(obj, dict):
            return obj
    except ImportError:
        raise ValueError("Output is not JSON; to parse YAML run: pip install pyyaml")
    except Exception:
        pass

    raise ValueError("Could not find a JSON/YAML payload in tool output. First 200 chars: " + text[:200].replace("\n", " "))


def _get(d, *path, default=None):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
    return default if d is None else d


def build_reasons(p: dict) -> list:
    reasons = []
    if p.get("auth_passed") is False:
        reasons.append("Email authentication (SPF/DKIM/DMARC) failed")
    if p.get("has_attachments"):
        reasons.append(f"{p.get('attachment_count', '?')} attachment(s) present")
    ue = p.get("url_enrichment") or {}
    for f in ue.get("triggered_flags") or []:
        reasons.append(f"URL flag: {f}")
    if ue.get("verdict"):
        reasons.append(f"URL reputation engines: {ue['verdict']} (threat score {ue.get('threat_score', 'n/a')})")
    bud = _get(p, "domain_analysis", "body_url_domain", default={})
    if bud.get("target_domain") and not _get(bud, "infrastructure_and_hosting", "resolved_ips"):
        reasons.append(f"Link domain {bud['target_domain']} does not resolve (possible dead/burner domain)")
    return reasons


def normalize_result(p: dict) -> dict:
    """Maps the tool payload to {verdict, severity, ...}. The tool's correlated severity decides."""
    explicit = str(p.get("final_verdict") or p.get("verdict") or "").lower()
    severity = str(p.get("alert_severity") or "").upper()
    if explicit in ("safe", "suspicious", "malicious"):
        verdict = explicit
    elif severity in SEVERITY_TO_VERDICT:
        verdict = SEVERITY_TO_VERDICT[severity]
    else:
        verdict = "suspicious"
        warn(f"Unknown severity '{severity or 'missing'}' -> treating as SUSPICIOUS (edit SEVERITY_TO_VERDICT)")
    return {
        "verdict": verdict,
        "severity": severity or "UNKNOWN",
        "score": _get(p, "url_enrichment", "threat_score", default="n/a"),
        "subject": p.get("subject", ""),
        "from": p.get("from", ""),
        "auth_passed": p.get("auth_passed"),
        "url": p.get("primary_analyzed_url", ""),
        "origin_ip": p.get("originating_ip", ""),
        "reasons": build_reasons(p),
        "raw": p,
    }


def run_analysis_tool(eml_path: Path, show: bool) -> dict:
    tool = Path(TOOL_SCRIPT)
    if not tool.is_absolute():
        tool = BASE_DIR / tool
    if not tool.exists():
        raise FileNotFoundError(f"Tool not found: {tool}")

    step(f"Running analysis tool: {tool.name}  (live output: {'ON' if show else 'OFF'})")
    rc, out, errtxt = run_tool_process(tool, eml_path, show)
    if rc != 0:
        raise RuntimeError(f"Tool exited {rc}: {errtxt.strip()[:300]}")
    if errtxt.strip() and not show:
        warn("Tool wrote to stderr (use --show-tool-output to see it)")
    return normalize_result(extract_payload(out))


def print_verdict(name: str, r: dict):
    col = {"safe": G, "suspicious": Y, "malicious": R}.get(r["verdict"], W)
    label = r["verdict"].upper()
    line = "═" * 62
    _out(f"\n{col}{BOLD}  ╔{line}╗")
    inner = f"  VERDICT: {label}   (tool severity: {r['severity']})"
    _out(f"  ║{inner:<62}║")
    _out(f"  ╚{line}╝{X}")
    _out(f"{W}  File     : {name}")
    _out(f"  Subject  : {r['subject'][:90]}")
    _out(f"  From     : {r['from'][:90]}")
    _out(f"  Auth     : {'PASSED' if r['auth_passed'] else 'FAILED' if r['auth_passed'] is False else 'n/a'}")
    _out(f"  URL      : {r['url'] or 'n/a'}")
    _out(f"  Orig. IP : {r['origin_ip'] or 'n/a'}{X}")
    for reason in r["reasons"]:
        _out(f"{Y}   • {reason}{X}")
    _out("")


# =====================================================================
#  BANNER INJECTION  (headers preserved; only the body gets the banner)
# =====================================================================
def inject_banner(raw: bytes, r: dict) -> bytes:
    verdict = r["verdict"]
    try:
        from email import message_from_bytes, policy
        msg = message_from_bytes(raw, policy=policy.default)

        color = {"safe": "#1e8e3e", "suspicious": "#f9ab00", "malicious": "#d93025"}[verdict]
        label = {"safe": "SAFE EMAIL", "suspicious": "SUSPICIOUS EMAIL", "malicious": "MALICIOUS EMAIL"}[verdict]
        items = "".join(f"<li>{html.escape(x)}</li>" for x in r["reasons"])
        banner_html = (
            f'<div style="font-family:Arial,sans-serif;background:{color};color:#fff;padding:12px 16px;'
            f'font-size:15px;border-radius:4px;margin:0 0 12px 0">'
            f'<b>&#128737; PHISHING SOC VERDICT: {label}</b><br>'
            f'<span style="font-size:12px">Tool severity: {html.escape(r["severity"])}</span>'
            f'<ul style="margin:6px 0 0 18px;padding:0;font-size:12px">{items}</ul></div>'
        )

        body = msg.get_body(preferencelist=("html",))
        if body is not None:
            h = body.get_content()
            if re.search(r"<body[^>]*>", h, re.I):
                h = re.sub(r"(<body[^>]*>)", lambda m: m.group(1) + banner_html, h, count=1, flags=re.I)
            else:
                h = banner_html + h
            body.set_content(h, subtype="html")
        else:
            plain = msg.get_body(preferencelist=("plain",))
            if plain is not None:
                plain.set_content(f"[PHISHING SOC VERDICT: {label} | severity {r['severity']}]\n\n" + plain.get_content())

        msg["X-SOC-Verdict"] = verdict
        msg["X-SOC-Severity"] = r["severity"]
        return msg.as_bytes()
    except Exception as e:
        warn(f"Banner injection failed ({type(e).__name__}: {e}); sending with X-SOC headers only")
        hdr = f"X-SOC-Verdict: {verdict}\r\nX-SOC-Severity: {r['severity']}\r\n".encode()
        return hdr + raw


# =====================================================================
#  PIPELINE PER EMAIL
# =====================================================================
def process_email(name: str, raw: bytes, eml_path: Path):
    if DELIVERY_MODE.upper() == "DIRECT":
        # ---- Testing path: no analysis, straight to inbox ----
        step(f"[DIRECT] Delivering {name} to {GMAIL_USER} ({SMTP_MODE}) ...")
        deliver_raw_smtp(raw)
        append_log(LOG_CUR_TMP, name, "DELIVERED_PENDING_ANALYSIS")
        ok(f"{name} delivered - logged in cur_tmp_eml.log (verdict pending)")
        return

    # ---- Analysis path ----
    append_log(LOG_CUR_TMP, name, "QUEUED_FOR_ANALYSIS")
    result = run_analysis_tool(eml_path, SHOW_TOOL_OUTPUT)
    print_verdict(name, result)

    final_raw = inject_banner(raw, result)
    verdict = result["verdict"]

    if verdict == "safe":
        step("Verdict SAFE -> delivering to INBOX ...")
        deliver_raw_smtp(final_raw)
        dest = "INBOX"
        ok(f"{name} delivered to inbox with SAFE banner")
    else:
        dest = QUARANTINE_FOLDER.get(verdict, "[Gmail]/Spam")
        step(f"Verdict {verdict.upper()} -> quarantining in {dest} ...")
        deliver_to_folder_imap(final_raw, dest)
        warn(f"{name} quarantined in {dest} with {verdict.upper()} banner")

    remove_from_log(LOG_CUR_TMP, name)
    append_log(LOG_FINAL, name, verdict.upper(), result["severity"], dest)
    ok("Logged in final_repo_eml.log")


def parse_args():
    ap = argparse.ArgumentParser(description="Phishing SOC Simulator - Section 1")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--direct", action="store_true", help="skip tool, deliver straight to inbox")
    mode.add_argument("--analyze", action="store_true", help="run tool then deliver by verdict")
    show = ap.add_mutually_exclusive_group()
    show.add_argument("--show-tool-output", action="store_true", help="stream tool output live")
    show.add_argument("--hide-tool-output", action="store_true", help="run tool silently")
    ap.add_argument("-n", type=int, help="number of samples this run")
    return ap.parse_args()


def main():
    global DELIVERY_MODE, SHOW_TOOL_OUTPUT, NUM_EMAILS
    args = parse_args()
    if args.direct:            DELIVERY_MODE = "DIRECT"
    if args.analyze:           DELIVERY_MODE = "ANALYZE"
    if args.show_tool_output:  SHOW_TOOL_OUTPUT = True
    if args.hide_tool_output:  SHOW_TOOL_OUTPUT = False
    if args.n:                 NUM_EMAILS = args.n

    banner()
    init_logs()
    info(f"Mode: {DELIVERY_MODE} | Tool output: {'VISIBLE' if SHOW_TOOL_OUTPUT else 'HIDDEN'} | Samples: {NUM_EMAILS}")

    if "PASTE_YOUR_APP_PASSWORD_HERE" in GMAIL_APP_PASSWORD:
        err("Add your Gmail App Password (GMAIL_APP_PASSWORD) at the top of the script first.")
        sys.exit(1)

    try:
        chosen = pick_new_emls(NUM_EMAILS)
    except requests.RequestException as e:
        err(f"GitHub API error: {e}")
        sys.exit(1)
    if not chosen:
        sys.exit(0)

    _out(f"{W}{'-' * 64}{X}")
    info("Selected samples: " + ", ".join(chosen))
    _out(f"{W}{'-' * 64}{X}")

    delivered = failed = 0
    tally = {"safe": 0, "suspicious": 0, "malicious": 0}
    for i, name in enumerate(chosen, 1):
        _out(f"\n{B}{BOLD}=== [{i}/{len(chosen)}] {name} ==={X}")
        try:
            step("Downloading from GitHub ...")
            raw = download_eml(name)
            eml_path = EML_DIR / name
            eml_path.write_bytes(raw)
            append_log(LOG_REPO_COUNTER, name, "FETCHED")
            ok(f"Fetched {name} ({len(raw)} bytes) -> logged in repo_eml_counter.log")

            process_email(name, raw, eml_path)
            delivered += 1
            last = LOG_FINAL.read_text(encoding="utf-8").strip().splitlines()[-1:] if DELIVERY_MODE.upper() == "ANALYZE" else []
            if last:
                v = last[0].split("|")[1].strip().lower()
                tally[v] = tally.get(v, 0) + 1
        except smtplib.SMTPAuthenticationError:
            err("Gmail authentication failed - check your App Password / 2-Step Verification.")
            failed += 1
            break
        except imaplib.IMAP4.error as e:
            err(f"{name}: IMAP error ({e}). Is IMAP enabled in Gmail settings?")
            failed += 1
        except Exception as e:
            err(f"{name}: {type(e).__name__}: {e}")
            failed += 1
        if i < len(chosen):
            time.sleep(DELAY_BETWEEN_SENDS)

    _out(f"\n{W}{'=' * 64}{X}")
    _out(f"{G}  Delivered : {delivered}{X}")
    if DELIVERY_MODE.upper() == "ANALYZE":
        _out(f"{G}  Safe      : {tally['safe']}{X}   {Y}Suspicious : {tally['suspicious']}{X}   {R}Malicious : {tally['malicious']}{X}")
    _out(f"{R if failed else W}  Failed    : {failed}{X}")
    _out(f"{Y}  Pending   : {len(read_names(LOG_CUR_TMP))} (cur_tmp_eml.log){X}")
    _out(f"{B}  Finalized : {len(read_names(LOG_FINAL))} (final_repo_eml.log){X}")
    _out(f"{W}{'=' * 64}{X}")


if __name__ == "__main__":
    main()
