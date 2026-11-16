#!/usr/bin/env python3
"""
The KingPhisher-Man - SECTION 2  (Live Mailbox Guard)

Flow:  your private account --(real email)--> target Gmail inbox
   1. LISTEN   : watch the target mailbox (Inbox + Spam) for mail FROM ONE specific sender
   2. ARCHIVE  : instantly pull the mail out of Inbox/Spam so the user never sees it
   3. DOWNLOAD : fetch the full raw .eml (original bytes) and save it locally
   4. ANALYZE  : run your analysis tool on that .eml
   5. RELEASE  : add the verdict banner, then remove the original so ONE message remains:
                   safe       -> put it into the INBOX
                   otherwise  -> put it into SPAM
   Logs: tmp_hold_eml.log (held, unverified)  ->  final_eml_output.log (verdict recorded)

Gives up with "no new mail found" if nothing arrives from the sender within 2 minutes.

Requires:  pip install pyyaml   (optional, only if your tool ever emits YAML)
Gmail:     IMAP enabled + App Password (same one as Section 1)

Usage:
  python section2_live_guard.py
  python section2_live_guard.py --continuous          # keep guarding after the first mail
  python section2_live_guard.py --hide-tool-output
  python section2_live_guard.py --timeout 180 --sender me@gmail.com
"""

import os
import re
import sys
import json
import html
import time
import uuid
import argparse
import imaplib
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from email import message_from_bytes, policy
from email.utils import parseaddr, getaddresses, make_msgid

# =====================================================================
#  CONFIGURATION  (edit this block)
# =====================================================================

# The mailbox being protected. The script logs into THIS account only.
TARGET_EMAIL = "Enter your GMAIL USER HERE"  # e.g. "yourname@gmail.com"

# >>> THE SENDER YOU ARE ALLOWED TO ANALYZE <<<
# ONLY mail whose From: address equals this is touched. Everything else is ignored completely.
ATTACKER_EMAIL = "yourname@gmail.com"  # e.g. "attacker@gmail.com"

# >>> PUT YOUR GOOGLE APP PASSWORD HERE <<<  (spaces are fine)
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "Enter your GMAIL APP PASSWORD HERE")

IMAP_HOST = "imap.gmail.com"
MONITORED_FOLDERS = ["INBOX", "[Gmail]/Spam"]     # where new mail may land

# RECOMMENDED (zero-visibility hold): create a Gmail filter  From: <ATTACKER_EMAIL>  ->
#   "Skip the Inbox (Archive it)" + "Apply the label: SOC-Hold" + "Never send it to Spam".
# Gmail then hides the mail the instant it is delivered, before this script even sees it.
# Put the label name here and the script will watch it too. Leave "" if you did not create the filter.
HOLD_LABEL_FOLDER = ""                            # e.g. "SOC-Hold"
ALL_MAIL_FOLDER = "[Gmail]/All Mail"              # where archived mail lives
POLL_INTERVAL = 1.0                               # seconds between checks (lower = faster archive)
WAIT_TIMEOUT = 120                                # give up after this many seconds with no mail
EXIT_AFTER_FIRST_MAIL = False                      # False (or --continuous) = keep guarding

STRICT_RECIPIENT_CHECK = False   # True = also require TARGET_EMAIL in To/Cc/Delivered-To headers

# What happens to the ORIGINAL (unbannered) message once the bannered copy is delivered.
# The untouched original is ALWAYS saved locally in eml_held/ first, so nothing is lost.
#   "TRASH"         = move original to Trash (hidden from normal views; Gmail purges it after 30 days)  <- default
#   "DELETE"        = permanently delete the original
#   "KEEP_ARCHIVED" = leave it in All Mail (you will then see TWO messages in the thread)
ORIGINAL_HANDLING = "TRASH"
TRASH_FOLDER = "[Gmail]/Trash"

# ---- Analysis tool -------------------------------------------------


# Directory containing kingphisher_ui_2.py
BASE_DIR = Path(__file__).resolve().parent

# Root directory: The-KingPhisher-Man
ROOT_DIR = BASE_DIR.parent

# Main email analysis tool (located in repository root)
TOOL_SCRIPT = str(
    ROOT_DIR / "email_data_extractor1.1_Tool_Github.py"
)

SHOW_TOOL_OUTPUT = True          # True = stream tool output live | False = silent
TOOL_TIMEOUT = 300

# The tool's correlated verdict (alert_severity) is the real verdict.

SEVERITY_TO_VERDICT = {
    "CRITICAL": "malicious", "HIGH": "malicious",
    "MEDIUM": "suspicious",
    "LOW": "safe", "INFO": "safe", "INFORMATIONAL": "safe",
    "NONE": "safe", "CLEAN": "safe", "SAFE": "safe",
}
QUARANTINE_FOLDER = {"malicious": "[Gmail]/Spam", "suspicious": "[Gmail]/Spam"}  # or "[Gmail]/Trash"

# ---- Paths ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
EML_DIR = BASE_DIR / "eml_held"
LOG_HOLD = LOG_DIR / "tmp_hold_eml.log"          # held + unverified
LOG_FINAL = LOG_DIR / "final_eml_output.log"     # verdict recorded

# =====================================================================
#  TERMINAL OUTPUT
# =====================================================================
os.system("")  # ANSI colors on Windows
W, G, B, Y, R, X = "\033[97m", "\033[92m", "\033[94m", "\033[93m", "\033[91m", "\033[0m"
GRAY, BOLD, C = "\033[90m", "\033[1m", "\033[96m"
_lock = threading.Lock()
_SEEN_IDS = set()   # Gmail message ids already handled this run
WATCH = []          # folders actually being watched (built at startup)


def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _out(s):
    with _lock:
        sys.stdout.write("\r\033[K" + s + "\n")
        sys.stdout.flush()


def status_line(s):
    with _lock:
        sys.stdout.write("\r\033[K" + s)
        sys.stdout.flush()


def info(m):  _out(f"{W}[{ts()}] [INFO]   {m}{X}")
def ok(m):    _out(f"{G}[{ts()}] [ OK ]   {m}{X}")
def step(m):  _out(f"{B}[{ts()}] [STEP]   {m}{X}")
def warn(m):  _out(f"{Y}[{ts()}] [WARN]   {m}{X}")
def err(m):   _out(f"{R}[{ts()}] [FAIL]   {m}{X}")


def phase(n, title):
    _out(f"\n{C}{BOLD}━━━ PHASE {n}/5 ▸ {title} " + "━" * max(2, 46 - len(title)) + X)


def banner():
    _out(f"{B}{BOLD}")
    _out("  ╔══════════════════════════════════════════════════════╗")
    _out("  ║     The KingPhisher-Man is Phishing for Phishes      ║")
    _out("  ║            $ ./Terminal Based Version                ║")
    _out("  ╚══════════════════════════════════════════════════════╝")
    _out(X)


def show_usage():
    _out(f"\n{C}{BOLD}  ━━━ AVAILABLE COMMANDS ━━━{X}")

    commands = [
        ("python section-2_live_guard.py",
         "Start monitoring (continuous mode)"),

        ("python section-2_live_guard.py --continuous",
         "Explicitly enable continuous monitoring"),

        ("python section-2_live_guard.py --hide-tool-output",
         "Hide analyzer output during execution"),

        ("python section-2_live_guard.py --timeout 180",
         "Set inactivity timeout to 180 seconds"),

        ("python section-2_live_guard.py --sender attacker@gmail.com",
         "Monitor emails from a specific sender"),

        ("python section-2_live_guard.py --timeout 180 --sender attacker@gmail.com",
         "Combine timeout and sender options"),
    ]

    for command, description in commands:
        _out(f"{G}  $ {command}{X}")
        _out(f"{GRAY}    {description}{X}")

    _out(f"\n{Y}  Press Ctrl+C to stop monitoring manually.{X}")
    _out(f"{C}  ━━━━━━━━━━━━━━━━━━━━━━━━━━{X}\n")



# =====================================================================
#  LOGS
# =====================================================================
def init_logs():
    LOG_DIR.mkdir(exist_ok=True)
    EML_DIR.mkdir(exist_ok=True)
    for f in (LOG_HOLD, LOG_FINAL):
        f.touch(exist_ok=True)


def clean(s):
    return str(s).replace("|", "/").replace("\n", " ").replace("\r", " ").strip()


def append_log(logfile, *cols):
    with open(logfile, "a", encoding="utf-8") as fh:
        fh.write(" | ".join(clean(c) for c in cols) + "\n")


def remove_from_log(logfile, name):
    lines = logfile.read_text(encoding="utf-8", errors="ignore").splitlines()
    kept = [l for l in lines if l.split("|")[0].strip() != name]
    logfile.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")


def count_lines(logfile):
    return len([l for l in logfile.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()])


# =====================================================================
#  IMAP / GMAIL HELPERS
# =====================================================================
def q(folder):
    return folder if folder.upper() == "INBOX" else f'"{folder}"'


def imap_connect():
    m = imaplib.IMAP4_SSL(IMAP_HOST, timeout=30)
    m.login(TARGET_EMAIL, GMAIL_APP_PASSWORD.replace(" ", ""))
    return m


def folder_baseline(m, folder):
    """Highest existing UID in a folder; only mail ABOVE this counts as 'new'."""
    typ, data = m.status(q(folder), "(UIDNEXT)")
    if typ != "OK":
        raise RuntimeError(f"Cannot read folder {folder}: {data}")
    return int(re.search(rb"UIDNEXT (\d+)", data[0]).group(1)) - 1


def find_new(m, folder, last_uid):
    typ, _ = m.select(q(folder))
    if typ != "OK":
        raise RuntimeError(f"Cannot open folder {folder}")
    typ, data = m.uid("SEARCH", None, "UID", f"{last_uid + 1}:*", "FROM", f'"{ATTACKER_EMAIL}"')
    uids = [int(x) for x in data[0].split()] if typ == "OK" and data and data[0] else []
    return sorted(u for u in uids if u > last_uid)


def fetch_meta(m, uid):
    typ, data = m.uid("FETCH", str(uid),
                      "(X-GM-MSGID BODY.PEEK[HEADER.FIELDS (FROM TO CC DELIVERED-TO SUBJECT DATE MESSAGE-ID X-SOC-ID)])")
    if typ != "OK" or not data:
        raise RuntimeError("Header fetch failed")
    blob = b" ".join(x[0] if isinstance(x, tuple) else (x or b"") for x in data)
    mid = re.search(rb"X-GM-MSGID (\d+)", blob)
    hdr_bytes = next((x[1] for x in data if isinstance(x, tuple)), b"")
    if not mid:
        raise RuntimeError("Gmail did not return X-GM-MSGID (is this a Gmail account with IMAP enabled?)")
    return mid.group(1).decode(), message_from_bytes(hdr_bytes, policy=policy.default)


def sender_matches(hdr) -> bool:
    return parseaddr(str(hdr.get("From", "")))[1].strip().lower() == ATTACKER_EMAIL.strip().lower()


def recipient_matches(hdr) -> bool:
    fields = [str(hdr.get(k, "")) for k in ("To", "Cc", "Delivered-To")]
    addrs = {a.lower() for _, a in getaddresses(fields)}
    return TARGET_EMAIL.lower() in addrs


def still_in_folder(m, folder, uid) -> bool:
    for _ in range(3):
        m.select(q(folder))
        typ, data = m.uid("SEARCH", None, "UID", str(uid))
        if not (typ == "OK" and data and data[0]):
            return False
        time.sleep(0.3)
    return True


def archive_message(m, folder, uid) -> str:
    """
    Hide the mail from the user. Returns 'pre-archived' | 'archived' | 'archived-fallback'.
    Raises if the mail is STILL visible afterwards (so you are never told it is hidden when it is not).
    """
    if folder.upper() != "INBOX" and folder != "[Gmail]/Spam":
        return "pre-archived"      # e.g. SOC-Hold label folder: the Gmail filter already hid it
    label = r"(\Inbox)" if folder.upper() == "INBOX" else r"(\Spam)"
    typ, data = m.uid("STORE", str(uid), "-X-GM-LABELS", label)
    if typ != "OK":
        raise RuntimeError(f"Archive failed: {data}")
    if not still_in_folder(m, folder, uid):
        return "archived"
    if folder.upper() == "INBOX":   # fallback: in Gmail, expunging from INBOX archives (never used on Spam)
        m.uid("STORE", str(uid), "+FLAGS", r"(\Deleted)")
        m.expunge()
        if not still_in_folder(m, folder, uid):
            return "archived-fallback"
    raise RuntimeError(f"Mail is STILL visible in {folder} after the archive attempt")


def fetch_raw_from_all_mail(m, msgid):
    """Locate the archived message by its Gmail message id and download the raw RFC822 bytes."""
    for _ in range(20):
        typ, _ = m.select(q(ALL_MAIL_FOLDER))
        if typ != "OK":
            raise RuntimeError(f"Cannot open {ALL_MAIL_FOLDER} (localized Gmail? edit ALL_MAIL_FOLDER)")
        typ, data = m.uid("SEARCH", "X-GM-MSGID", msgid)
        if typ == "OK" and data and data[0]:
            am_uid = data[0].split()[-1].decode()
            typ, fdata = m.uid("FETCH", am_uid, "(BODY.PEEK[])")
            if typ == "OK" and fdata and isinstance(fdata[0], tuple):
                return fdata[0][1], am_uid
        time.sleep(0.5)
    raise RuntimeError("Archived message not found in All Mail")


def remove_original(m, msgid, am_uid) -> str:
    """Gets rid of the untouched original so only ONE (bannered) message remains. Returns kept|trashed|deleted."""
    mode = ORIGINAL_HANDLING.upper()
    if mode == "KEEP_ARCHIVED":
        return "kept"
    m.select(q(ALL_MAIL_FOLDER))
    typ, data = m.uid("STORE", str(am_uid), "+X-GM-LABELS", r"(\Trash)")
    if typ != "OK":
        raise RuntimeError(f"Could not move original to Trash: {data}")
    if mode == "DELETE":
        for _ in range(6):
            m.select(q(TRASH_FOLDER))
            typ, data = m.uid("SEARCH", "X-GM-MSGID", msgid)
            if typ == "OK" and data and data[0]:
                m.uid("STORE", data[0].split()[-1].decode(), "+FLAGS", r"(\Deleted)")
                m.expunge()
                return "deleted"
            time.sleep(0.5)
        warn("Original is in Trash but could not be permanently deleted; Gmail will purge it in 30 days")
    return "trashed"


def verify_delivery(m, folder, token):
    """Returns the Gmail message id of the newly delivered copy, or None if it is not there."""
    for _ in range(10):
        typ, _ = m.select(q(folder))
        if typ == "OK":
            typ, data = m.uid("SEARCH", None, "HEADER", "X-SOC-Id", token)
            if typ == "OK" and data and data[0]:
                new_uid = data[0].split()[-1].decode()
                typ, fd = m.uid("FETCH", new_uid, "(X-GM-MSGID)")
                blob = b" ".join(x[0] if isinstance(x, tuple) else (x or b"") for x in (fd or []))
                mm = re.search(rb"X-GM-MSGID (\d+)", blob)
                return mm.group(1).decode() if mm else "unknown"
        time.sleep(0.5)
    return None


# =====================================================================
#  ANALYSIS TOOL
# =====================================================================
def _pump(stream, bucket, show, color):
    for line in iter(stream.readline, ""):
        bucket.append(line)
        if show:
            _out(f"{color}  │ {line.rstrip()}{X}")
    stream.close()


def run_tool_process(tool: Path, eml_path: Path, show: bool):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [sys.executable, str(tool), str(eml_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
        cwd=str(tool.parent), env=env, bufsize=1,
    )
    out_l, err_l = [], []
    t1 = threading.Thread(target=_pump, args=(proc.stdout, out_l, show, GRAY), daemon=True)
    t2 = threading.Thread(target=_pump, args=(proc.stderr, err_l, show, Y), daemon=True)
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
    return proc.returncode, "".join(out_l), "".join(err_l)


def extract_payload(text: str) -> dict:
    """Header line + pretty JSON, compact JSON, or YAML."""
    text = text.strip()
    if not text:
        raise ValueError("Tool produced no output on stdout")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass
    dec = json.JSONDecoder()
    best, best_len = None, 0
    for mt in re.finditer(r"(?m)^\{", text):
        try:
            obj, end = dec.raw_decode(text[mt.start():])
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
    except ImportError:
        raise ValueError("Output is not JSON; for YAML run: pip install pyyaml")
    except Exception:
        pass
    raise ValueError("No JSON/YAML payload found. First 200 chars: " + text[:200].replace("\n", " "))


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
        "verdict": verdict, "severity": severity or "UNKNOWN",
        "score": _get(p, "url_enrichment", "threat_score", default="n/a"),
        "subject": p.get("subject", ""), "from": p.get("from", ""),
        "auth_passed": p.get("auth_passed"), "url": p.get("primary_analyzed_url", ""),
        "origin_ip": p.get("originating_ip", ""), "reasons": build_reasons(p), "raw": p,
    }


def run_analysis_tool(eml_path: Path) -> dict:
    tool = Path(TOOL_SCRIPT)
    if not tool.is_absolute():
        tool = BASE_DIR / tool
    if not tool.exists():
        raise FileNotFoundError(f"Tool not found: {tool}")
    step(f"Running analysis tool: {tool.name}  (live output: {'ON' if SHOW_TOOL_OUTPUT else 'OFF'})")
    rc, out, errtxt = run_tool_process(tool, eml_path, SHOW_TOOL_OUTPUT)
    if rc != 0:
        raise RuntimeError(f"Tool exited {rc}: {errtxt.strip()[:300]}")
    return normalize_result(extract_payload(out))


def print_verdict(name: str, r: dict):
    col = {"safe": G, "suspicious": Y, "malicious": R}.get(r["verdict"], W)
    line = "═" * 62
    inner = f"  VERDICT: {r['verdict'].upper()}   (tool severity: {r['severity']})"
    _out(f"\n{col}{BOLD}  ╔{line}╗")
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
#  BANNER + RELEASE
# =====================================================================
def inject_banner(raw: bytes, r: dict, token: str, rewrite_id: bool = False) -> bytes:
    """Original headers kept. Banner goes into the body; X-SOC-* headers are added."""
    verdict = r["verdict"]
    try:
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
                h = re.sub(r"(<body[^>]*>)", lambda mt: mt.group(1) + banner_html, h, count=1, flags=re.I)
            else:
                h = banner_html + h
            body.set_content(h, subtype="html")
        else:
            plain = msg.get_body(preferencelist=("plain",))
            if plain is not None:
                plain.set_content(f"[PHISHING SOC VERDICT: {label} | severity {r['severity']}]\n\n" + plain.get_content())

        if rewrite_id:
            old = msg.get("Message-ID")
            if old:
                msg["X-Original-Message-ID"] = str(old)
                del msg["Message-ID"]
            msg["Message-ID"] = make_msgid(domain="soc.local")
        msg["X-SOC-Verdict"] = verdict
        msg["X-SOC-Severity"] = r["severity"]
        msg["X-SOC-Id"] = token
        return msg.as_bytes()
    except Exception as e:
        warn(f"Banner injection failed ({type(e).__name__}: {e}); using X-SOC headers only")
        hdr = f"X-SOC-Verdict: {verdict}\r\nX-SOC-Severity: {r['severity']}\r\nX-SOC-Id: {token}\r\n".encode()
        return hdr + raw


def release_message(m, raw: bytes, r: dict, dest_folder: str):
    """APPEND the bannered copy into dest_folder and verify it is really there."""
    token = uuid.uuid4().hex
    for attempt, rewrite in enumerate((False, True), 1):
        data = inject_banner(raw, r, token, rewrite_id=rewrite)
        data = re.sub(rb"\r?\n", b"\r\n", data)
        typ, resp = m.append(q(dest_folder), None, imaplib.Time2Internaldate(time.time()), data)
        if typ != "OK":
            raise RuntimeError(f"APPEND to {dest_folder} failed: {resp}")
        new_id = verify_delivery(m, dest_folder, token)
        if new_id:
            if rewrite:
                warn("Gmail merged the duplicate Message-ID; delivered with a NEW Message-ID "
                     "(original kept in X-Original-Message-ID)")
            return rewrite, new_id
        if attempt == 1:
            warn("Bannered copy not visible (Gmail de-duplicated on Message-ID) -> retrying with a new Message-ID")
    raise RuntimeError(f"Could not confirm delivery into {dest_folder}")


# =====================================================================
#  PER-MESSAGE PIPELINE
# =====================================================================
def handle_message(m, folder: str, uid: int) -> bool:
    t_detect = time.time()
    msgid, hdr = fetch_meta(m, uid)
    if hdr.get("X-SOC-Id"):          # our own released copy - never re-process it
        return False
    if msgid in _SEEN_IDS:           # same Gmail message seen via another folder/label
        return False
    subject = str(hdr.get("Subject", "(no subject)"))
    from_hdr = str(hdr.get("From", ""))

    # ---- GATE: strictly the configured sender (and optionally recipient) ----
    if not sender_matches(hdr):
        info(f"Ignored UID {uid} in {folder}: sender '{parseaddr(from_hdr)[1]}' is not {ATTACKER_EMAIL}")
        return False
    if STRICT_RECIPIENT_CHECK and not recipient_matches(hdr):
        info(f"Ignored UID {uid}: {TARGET_EMAIL} not in To/Cc/Delivered-To")
        return False

    _SEEN_IDS.add(msgid)
    _out(f"\n{Y}{BOLD}  ⚠  TARGET MAIL DETECTED in {folder}{X}")
    _out(f"{W}     From    : {from_hdr}\n     Subject : {subject}\n     Gmail ID: {msgid}{X}")

    eml_name = f"{datetime.now():%Y%m%d_%H%M%S}_{msgid}.eml"
    arrived = str(hdr.get("Date", "unknown"))
    detected_at = ts()

    # ---------------- PHASE 2: ARCHIVE ----------------
    phase(2, "INSTANT ARCHIVE")
    step(f"Hiding mail from the user ({folder}) ...")
    how = archive_message(m, folder, uid)
    ms = int((time.time() - t_detect) * 1000)
    if how == "pre-archived":
        ok(f"Already hidden by your Gmail filter (never reached the Inbox). Detected in {ms} ms")
    else:
        ok(f"Archived and VERIFIED gone from {folder} - user cannot see it. Detection -> archive: {ms} ms"
           + ("  (fallback method used)" if how == "archived-fallback" else ""))
    append_log(LOG_HOLD, eml_name, "HELD_ARCHIVED", msgid, from_hdr, subject, f"arrived={arrived}", f"detected={detected_at}")
    ok("Logged in tmp_hold_eml.log (held, unverified)")

    stage = "DOWNLOAD"
    try:
        # ---------------- PHASE 3: DOWNLOAD ----------------
        phase(3, "DOWNLOAD .EML")
        step("Locating archived mail in All Mail and downloading raw message ...")
        raw, am_uid = fetch_raw_from_all_mail(m, msgid)
        eml_path = EML_DIR / eml_name
        eml_path.write_bytes(raw)
        ok(f"Saved {eml_name} ({len(raw)} bytes) -> {EML_DIR.name}/")

        # ---------------- PHASE 4: ANALYZE ----------------
        stage = "ANALYSIS"
        phase(4, "ANALYSIS")
        result = run_analysis_tool(eml_path)
        print_verdict(eml_name, result)

        # ---------------- PHASE 5: RELEASE ----------------
        stage = "RELEASE"
        phase(5, "VERDICT & RELEASE")
        verdict = result["verdict"]
        dest = "INBOX" if verdict == "safe" else QUARANTINE_FOLDER.get(verdict, "[Gmail]/Spam")
        step(f"Verdict {verdict.upper()} -> adding banner and delivering to {dest} ...")
        _, new_id = release_message(m, raw, result, dest)
        if verdict == "safe":
            ok("SAFE banner added - mail is now visible in the user's INBOX")
        else:
            warn(f"{verdict.upper()} banner added - mail placed in {dest}")

        if new_id == msgid:
            warn("Delivered copy is the SAME Gmail message as the original - original left untouched")
        else:
            outcome = remove_original(m, msgid, am_uid)
            if outcome == "kept":
                info("Original kept archived in All Mail (you will see 2 messages in the thread)")
            elif outcome == "deleted":
                ok("Original permanently deleted (untouched copy is saved in eml_held/)")
            else:
                ok("Original moved to Trash (untouched copy is saved in eml_held/)")
            if outcome != "kept":
                ok(f"Final state: exactly ONE message visible, in {dest}")

        remove_from_log(LOG_HOLD, eml_name)
        append_log(LOG_FINAL, eml_name, verdict.upper(), result["severity"], from_hdr, subject,
                   f"arrived={arrived}", f"detected={detected_at}", f"verdict_at={ts()}",
                   f"destination={dest}", f"gmail_id={msgid}")
        ok("Moved from tmp_hold_eml.log -> final_eml_output.log")
        return True

    except Exception as e:
        err(f"{stage} failed: {type(e).__name__}: {e}")
        warn("Mail stays ARCHIVED and listed in tmp_hold_eml.log (fail-closed: user never sees it unverified)")
        append_log(LOG_HOLD, eml_name, f"FAILED_AT_{stage}", msgid, from_hdr, subject, f"error={e}")
        remove_dupe_hold(eml_name)
        return True


def remove_dupe_hold(eml_name):
    """Keep only the newest hold-log line for this file (the FAILED one)."""
    lines = LOG_HOLD.read_text(encoding="utf-8", errors="ignore").splitlines()
    mine = [i for i, l in enumerate(lines) if l.split("|")[0].strip() == eml_name]
    for i in reversed(mine[:-1]):
        lines.pop(i)
    LOG_HOLD.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# =====================================================================
#  MAIN LOOP
# =====================================================================
def mmss(sec):
    sec = max(0, int(sec))
    return f"{sec // 60:02d}:{sec % 60:02d}"


def parse_args():
    ap = argparse.ArgumentParser(description="The KingPhisher-Man - Section 2 (Live Mailbox Guard)")
    ap.add_argument("--continuous", action="store_true", help="keep guarding after the first mail")
    ap.add_argument("--timeout", type=int, help="seconds to wait for mail (default 120)")
    ap.add_argument("--sender", help="override ATTACKER_EMAIL for this run")
    s = ap.add_mutually_exclusive_group()
    s.add_argument("--show-tool-output", action="store_true")
    s.add_argument("--hide-tool-output", action="store_true")
    return ap.parse_args()


def build_baselines(m) -> dict:
    global WATCH
    folders = list(MONITORED_FOLDERS) + ([HOLD_LABEL_FOLDER] if HOLD_LABEL_FOLDER else [])
    base = {}
    for f in folders:
        try:
            base[f] = folder_baseline(m, f)
        except Exception as e:
            if f.upper() == "INBOX":
                raise
            warn(f"Skipping folder '{f}': {e}")
    WATCH = list(base)
    return base


def main():
    global ATTACKER_EMAIL, WAIT_TIMEOUT, EXIT_AFTER_FIRST_MAIL, SHOW_TOOL_OUTPUT
    a = parse_args()
    if a.sender:            ATTACKER_EMAIL = a.sender
    if a.timeout:           WAIT_TIMEOUT = a.timeout
    if a.continuous:        EXIT_AFTER_FIRST_MAIL = False
    if a.show_tool_output:  SHOW_TOOL_OUTPUT = True
    if a.hide_tool_output:  SHOW_TOOL_OUTPUT = False

    banner()
    init_logs()

# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

errors = []

# Validate protected Gmail account
if (
    not TARGET_EMAIL.strip()
    or TARGET_EMAIL.strip() == "Enter your GMAIL USER HERE"
    or "@" not in TARGET_EMAIL
):
    errors.append(
        "TARGET_EMAIL is not configured. "
        "Enter the Gmail address you want to protect."
    )

# Validate Gmail App Password
if (
    not GMAIL_APP_PASSWORD.strip()
    or GMAIL_APP_PASSWORD.strip() == "Enter your GMAIL APP PASSWORD HERE"
):
    errors.append(
        "GMAIL_APP_PASSWORD is missing. "
        "Configure your Gmail App Password before running."
    )

# Validate attacker email
if (
    not ATTACKER_EMAIL.strip()
    or ATTACKER_EMAIL.strip() == "Enter the ATTACKER EMAIL HERE"
    or "@" not in ATTACKER_EMAIL
):
    errors.append(
        "ATTACKER_EMAIL is not configured. "
        "Enter the sender address to monitor."
    )

# Stop execution if configuration is incomplete
if errors:
    _out(f"\n{R}{BOLD}  ━━━ CONFIGURATION ERROR ━━━{X}")

    for error in errors:
        err(error)

    _out(
        f"\n{Y}  Update your configuration and restart the script.{X}"
    )

    sys.exit(1)

# Warn if sender and recipient are identical
if ATTACKER_EMAIL.strip().lower() == TARGET_EMAIL.strip().lower():
    warn(
        "ATTACKER_EMAIL equals TARGET_EMAIL - "
        "the guard's own re-delivered mail could be re-detected."
    )

    
    _out(f"{W}  Protected mailbox : {TARGET_EMAIL}")
    _out(f"  Allowed sender    : {ATTACKER_EMAIL}   (all other senders are ignored)")
    _out(f"  Watching folders  : {', '.join(MONITORED_FOLDERS + ([HOLD_LABEL_FOLDER] if HOLD_LABEL_FOLDER else []))}")
    _out(f"  Timeout           : {WAIT_TIMEOUT}s | Tool output: {'VISIBLE' if SHOW_TOOL_OUTPUT else 'HIDDEN'} | "
         f"Mode: {'single mail' if EXIT_AFTER_FIRST_MAIL else 'continuous'}{X}")

    phase(1, "LISTENING")
    step(f"Connecting to {IMAP_HOST} as {TARGET_EMAIL} ...")
    try:
        m = imap_connect()
        baseline = build_baselines(m)
    except imaplib.IMAP4.error as e:
        err(f"IMAP login/setup failed: {e}  (enable IMAP in Gmail settings and use an App Password)")
        sys.exit(1)
    except Exception as e:
        err(f"Connection failed: {type(e).__name__}: {e}")
        sys.exit(1)
    ok("Connected. Existing mail is ignored - only NEW mail from the allowed sender is processed.")
    info(f"Now send your test email from {ATTACKER_EMAIL} to {TARGET_EMAIL} ...")

    deadline = time.time() + WAIT_TIMEOUT
    polls, processed = 0, 0
    spinner = "|/-\\"
    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                _out("")
                if processed == 0:
                    warn(f"No new mail from {ATTACKER_EMAIL} found within {WAIT_TIMEOUT}s. Terminating.")
                else:
                    info(f"No further mail within {WAIT_TIMEOUT}s. Terminating.")
                break
            try:
                handled_any = False
                for folder in WATCH:
                    for uid in find_new(m, folder, baseline[folder]):
                        baseline[folder] = max(baseline[folder], uid)
                        if handle_message(m, folder, uid):
                            processed += 1
                            handled_any = True
                        if handled_any and EXIT_AFTER_FIRST_MAIL:
                            break
                    if handled_any and EXIT_AFTER_FIRST_MAIL:
                        break
                if handled_any:
                    if EXIT_AFTER_FIRST_MAIL:
                        break
                    deadline = time.time() + WAIT_TIMEOUT
                    phase(1, "LISTENING")
                    continue
            except (imaplib.IMAP4.abort, OSError) as e:
                warn(f"Connection dropped ({type(e).__name__}); reconnecting ...")
                try:
                    m = imap_connect()
                except Exception as e2:
                    err(f"Reconnect failed: {e2}")
                    time.sleep(2)
                continue
            except Exception as e:
                err(f"Unexpected error while processing: {type(e).__name__}: {e}")

            polls += 1
            status_line(f"{C}  {spinner[polls % 4]} Listening for mail from {ATTACKER_EMAIL} | "
                        f"poll #{polls} | {Y}{mmss(remaining)}{C} left before timeout{X}")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        _out("")
        warn("Interrupted by user.")

    try:
        m.logout()
    except Exception:
        pass

    _out(f"\n{W}{'=' * 64}{X}")
    _out(f"{G}  Mails processed : {processed}{X}")
    _out(f"{Y}  Still held      : {count_lines(LOG_HOLD)}  (tmp_hold_eml.log){X}")
    _out(f"{B}  Finalized       : {count_lines(LOG_FINAL)}  (final_eml_output.log){X}")
    _out(f"{W}{'=' * 64}{X}")


if __name__ == "__main__":
    main()
