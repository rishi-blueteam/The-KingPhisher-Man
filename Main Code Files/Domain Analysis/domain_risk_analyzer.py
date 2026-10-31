#!/usr/bin/env python3
"""
Domain Risk Analyzer  -  4-tier, 12-indicator phishing-domain scoring engine
=============================================================================
Replaces BOTH  Domain_Analyzer.py  and  domain_intel_analyzer.py  (same output keys are kept,
so email_data_extractor1.py keeps working; see the compatibility wrappers at the bottom).

Free / open-source building blocks
  * Tranco top-1M list (local SQLite)  -> trust rank, TLD reputation, typosquat baseline
  * tldextract (bundled PSL snapshot)  -> registrable domain / subdomain split, works offline
  * rapidfuzz                          -> Levenshtein / Jaro-Winkler typosquat distance
  * cryptography                       -> real X.509 parsing (issuer, DV/OV/EV, SAN, validity)
  * dnspython                          -> DNS
  * IANA RDAP bootstrap + registry RDAP -> registration data (no rdap.org hop, no scraping)
  * ip-api.com (optional)              -> hosting / ASN / geo   (--no-geo to skip)

Speed: all network lookups (DNS, RDAP, TLS) run IN PARALLEL; Tranco is a local DB;
validated results are cached in logs/validated_domains.log.

Install:  pip install requests dnspython cryptography tldextract rapidfuzz

Usage:
  python domain_risk_analyzer.py example.com                 # JSON on stdout (pipeline mode)
  python domain_risk_analyzer.py example.com --report        # colorful human report
  python domain_risk_analyzer.py example.com --report --json # report on stderr, JSON on stdout
  python domain_risk_analyzer.py --update-tranco             # download/refresh Tranco list
  python domain_risk_analyzer.py --tranco-file top-1m.csv    # build Tranco DB from a local file
  python domain_risk_analyzer.py --list-cache                # show validated-domain log
  flags: --no-cache  --refresh  --no-geo
"""

import io
import os
import re
import sys
import ssl
import json
import math
import time
import socket
import sqlite3
import hashlib
import zipfile
import argparse
import ipaddress
import threading
import unicodedata
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
    import dns.resolver
    import dns.exception
    import tldextract
    from rapidfuzz.distance import Levenshtein, JaroWinkler
    from cryptography import x509
    from cryptography.x509.oid import NameOID
except ImportError as _e:  # pragma: no cover
    sys.stderr.write(f"[!] Missing dependency: {_e.name}\n"
                     "    Run: pip install requests dnspython cryptography tldextract rapidfuzz\n")
    sys.exit(2)

# =====================================================================
#  CONFIGURATION
# =====================================================================
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
CACHE_DIR = BASE_DIR / "cache"
VALIDATED_LOG = LOG_DIR / "validated_domains.log"       # JSON-lines, one record per analysed domain
TRANCO_DB = CACHE_DIR / "tranco.sqlite"
RDAP_BOOTSTRAP_FILE = CACHE_DIR / "rdap_dns_bootstrap.json"

TRANCO_URL = os.environ.get("TRANCO_LIST_URL", "https://tranco-list.eu/top-1m.csv.zip")
TRANCO_STALE_DAYS = 7                 # only a hint - refresh manually with --update-tranco
FAST_TRUST_RANK = 1000                # Tranco rank <= this (and no structural alarms) skips network checks. 0 = off
TYPO_BASELINE_TOP_N = 10000           # Tranco top-N used as the typosquat baseline
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

NRD_STRICT_DAYS = 30                  # doc: <14 days (<30 for strict environments)
NET_TIMEOUT = 4.0                     # per-request network timeout (seconds)
TLS_TIMEOUT = 3.0
OVERALL_DEADLINE = 8.0                # max seconds to wait for the parallel network phase

# validated-domain cache lifetime
TTL_BY_LEVEL = {"LOW": timedelta(days=7), "MEDIUM": timedelta(days=2),
                "HIGH": timedelta(days=1), "CRITICAL": timedelta(days=1)}
TTL_DEGRADED = timedelta(hours=6)     # when RDAP/Tranco were unavailable

# Risk levels (score 0-100)
LEVELS = [(85, "CRITICAL"), (60, "HIGH"), (20, "MEDIUM"), (0, "LOW")]
T1_FLOOR = 90                         # any Tier-1 hit forces the score to at least this

TIER_INFO = {
    1: ("TIER 1 - CRITICAL", "95%+ confidence · immediate block"),
    2: ("TIER 2 - HIGH", "75-90% confidence · strong signal"),
    3: ("TIER 3 - MEDIUM", "40-70% confidence · suspicious context"),
    4: ("TIER 4 - LOW", "10-35% confidence · anomalous baseline"),
}

HIGH_RISK_TLDS = {
    "xyz", "top", "cc", "live", "icu", "buzz", "tk",                      # from the risk table
    "ml", "ga", "cf", "gq", "click", "link", "rest", "cyou", "monster",   # commonly abused
    "sbs", "cfd", "work", "fit", "loan", "zip", "mov", "pw", "cam", "quest",
}

FREE_DV_ISSUERS = ("let's encrypt", "zerossl", "google trust services", "cloudflare",
                   "buypass", "actalis")

RISK_KEYWORDS = {
    "login", "signin", "verify", "verification", "security", "secure", "support", "update",
    "account", "accounts", "auth", "authenticate", "authentication", "confirm", "billing",
    "password", "recovery", "unlock", "wallet", "alert", "validate", "helpdesk",
}
COMMON_TLD_LABELS = {"com", "net", "org", "co", "in", "io", "us", "uk", "gov", "edu", "info", "biz", "br"}

PRIVACY_MARKERS = (
    "redacted", "privacy", "proxy", "whoisguard", "domains by proxy", "contact privacy",
    "withheld", "data protected", "perfect privacy", "identity protect", "private registration",
    "not disclosed", "anonymi", "registration private", "gdpr", "domain protection",
    "request email form", "rdds", "contact the registrar", "see registrar", "data redacted", "not available",
)

# =====================================================================
#  PROTECTED BRANDS  (brand token -> its official registrable domains)
#  Extend without editing code:  export BRANDS_FILE=my_brands.json   {"brand": ["official.com", ...]}
# =====================================================================
BRANDS = {
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
                  "outlook.com", "sharepoint.com", "onedrive.com", "azure.com", "msn.com", "bing.com", "skype.com", "xbox.com"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "office365": ["office365.com", "office.com", "microsoft.com", "microsoftonline.com"],
    "onedrive": ["onedrive.com", "live.com", "microsoft.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "goo.gl", "g.co", "googlemail.com"],
    "gmail": ["gmail.com", "google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com", "me.com", "cdn-apple.com", "mzstatic.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es", "amazon.it",
               "amazon.co.jp", "amazon.com.br", "amazon.ca", "amazon.com.au", "a.co", "amzn.to"],
    "aws": ["aws.com", "amazon.com", "amazonaws.com", "awsstatic.com"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com"],
    "netflix": ["netflix.com", "nflxso.net", "nflximg.net"],
    "facebook": ["facebook.com", "fb.com", "fb.me", "fbcdn.net", "messenger.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "twitter": ["twitter.com", "x.com", "t.co", "twimg.com"],
    "dropbox": ["dropbox.com", "getdropbox.com"],
    "adobe": ["adobe.com", "adobelogin.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "zoom": ["zoom.us", "zoom.com"],
    "slack": ["slack.com", "slack-edge.com"],
    "github": ["github.com"],
    "gitlab": ["gitlab.com"],
    "ebay": ["ebay.com", "ebay.co.uk", "ebay.de", "ebay.in"],
    "walmart": ["walmart.com"],
    "chase": ["chase.com", "jpmorgan.com", "jpmorganchase.com"],
    "jpmorgan": ["jpmorgan.com", "jpmorganchase.com", "chase.com"],
    "wellsfargo": ["wellsfargo.com", "wf.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com", "ml.com"],
    "citibank": ["citibank.com", "citi.com", "citigroup.com"],
    "americanexpress": ["americanexpress.com", "aexp.com"],
    "capitalone": ["capitalone.com"],
    "usbank": ["usbank.com"],
    "hsbc": ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk", "hsbc.co.in"],
    "barclays": ["barclays.com", "barclays.co.uk", "barclaycard.co.uk"],
    "santander": ["santander.com", "santander.co.uk", "santander.com.br"],
    "bradesco": ["bradesco.com.br", "bradescoseguros.com.br", "banco.bradesco"],
    "itau": ["itau.com.br", "itau.com"],
    "nubank": ["nubank.com.br"],
    "livelo": ["livelo.com.br"],
    "bancodobrasil": ["bb.com.br"],
    "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"],
    "onlinesbi": ["onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "flipkart": ["flipkart.com"],
    "airtel": ["airtel.in", "airtel.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "coinbase": ["coinbase.com"],
    "binance": ["binance.com", "binance.us"],
    "metamask": ["metamask.io"],
    "kraken": ["kraken.com"],
    "stripe": ["stripe.com"],
    "shopify": ["shopify.com"],
    "spotify": ["spotify.com", "scdn.co"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "yahoo": ["yahoo.com", "ymail.com"],
    "wetransfer": ["wetransfer.com", "we.tl"],
    "att": ["att.com"],
    "verizon": ["verizon.com", "vzw.com"],
    "xfinity": ["xfinity.com", "comcast.com", "comcast.net"],
    "mercadolibre": ["mercadolibre.com", "mercadopago.com"],
    "telegram": ["telegram.org", "t.me"],
    "tiktok": ["tiktok.com"],
    "roblox": ["roblox.com"],
    "booking": ["booking.com"],
    "airbnb": ["airbnb.com"],
    "okta": ["okta.com"],
}
if os.environ.get("BRANDS_FILE") and Path(os.environ["BRANDS_FILE"]).is_file():
    try:
        BRANDS.update({k.lower(): [d.lower() for d in v]
                       for k, v in json.loads(Path(os.environ["BRANDS_FILE"]).read_text("utf-8")).items()})
    except Exception:
        pass

# Confusable characters -> ASCII look-alike (skeleton)
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ɑ": "a", "ѵ": "v", "к": "k", "м": "m",
    "т": "t", "н": "h", "в": "b", "ց": "g", "օ": "o", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i",
    "υ": "u", "κ": "k", "χ": "x", "τ": "t", "ℓ": "l", "ǀ": "l", "ꓲ": "l", "Ι": "i", "Β": "b", "ß": "b",
}

OFFICIAL_ALL = {d for ds in BRANDS.values() for d in ds}

# =====================================================================
#  TERMINAL COLORS
# =====================================================================
os.system("")
W, G, B, Y, R, X = "\033[97m", "\033[92m", "\033[94m", "\033[93m", "\033[91m", "\033[0m"
GRAY, BOLD, C, M = "\033[90m", "\033[1m", "\033[96m", "\033[95m"


def now_utc():
    return datetime.now(timezone.utc)


# =====================================================================
#  DOMAIN NORMALISATION
# =====================================================================
_TLDX = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)   # bundled snapshot, no network


def extract_apex_domain(input_str: str) -> str:
    """URL or raw string -> clean lowercase ASCII host (handles ports, user@host tricks, IDN)."""
    s = (input_str or "").strip()
    if "://" not in s:
        s = "http://" + s
    try:
        host = urlparse(s).hostname or ""
    except ValueError:
        host = ""
    host = host.strip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return host


def decode_label(label: str) -> str:
    """xn-- label -> unicode. Falls back to raw punycode when strict IDNA refuses (as it must for fake IDNs)."""
    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except Exception:
        try:
            return label[4:].encode("ascii").decode("punycode")
        except Exception:
            return label


def script_of(ch: str) -> str:
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"


def skeleton(text: str) -> str:
    """Fold look-alike characters and diacritics to plain ASCII."""
    out = []
    for ch in text:
        ch = CONFUSABLES.get(ch, ch)
        nk = unicodedata.normalize("NFKD", ch)
        out.append("".join(c for c in nk if not unicodedata.combining(c)))
    return "".join(out).lower()


def tokens(s: str):
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def brand_in_tokens(brand: str, toks) -> bool:
    for t in toks:
        if t == brand or (len(brand) >= 6 and brand in t):
            return True
    return False


def build_context(host: str) -> dict:
    try:
        ipaddress.ip_address(host)
        return {"host": host, "is_ip": True, "subdomain": "", "sld": "", "suffix": "", "tld": "",
                "registrable": host, "unicode_host": host}
    except ValueError:
        pass
    ext = _TLDX(host)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host
    unicode_host = ".".join(decode_label(l) for l in host.split("."))
    return {"host": host, "is_ip": False, "subdomain": ext.subdomain, "sld": ext.domain,
            "suffix": ext.suffix, "tld": ext.suffix.split(".")[-1] if ext.suffix else "",
            "registrable": registrable, "unicode_host": unicode_host}


# =====================================================================
#  TRANCO STORE  (local SQLite - instant lookups)
# =====================================================================
class TrancoStore:
    def __init__(self, path: Path):
        self.path, self.conn = path, None
        if path.is_file():
            try:
                self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
                self.conn.execute("SELECT 1 FROM tranco LIMIT 1")
            except sqlite3.Error:
                self.conn = None

    @property
    def available(self):
        return self.conn is not None

    def rank(self, domain: str):
        if not self.conn:
            return None
        row = self.conn.execute("SELECT rank FROM tranco WHERE domain=?", (domain,)).fetchone()
        return row[0] if row else None

    def tld_count_top100k(self, tld: str):
        if not self.conn or not tld:
            return None
        return self.conn.execute("SELECT COUNT(*) FROM tranco WHERE rank<=100000 AND tld=?", (tld,)).fetchone()[0]

    def baseline(self, n: int):
        """[(sld, domain)] for the top-n ranked domains."""
        if not self.conn:
            return []
        return self.conn.execute("SELECT sld, domain FROM tranco WHERE rank<=? AND sld IS NOT NULL", (n,)).fetchall()

    def age_days(self):
        if not self.conn:
            return None
        try:
            row = self.conn.execute("SELECT v FROM meta WHERE k='downloaded_at'").fetchone()
            return (now_utc() - datetime.fromisoformat(row[0])).days if row else None
        except sqlite3.Error:
            return None


def build_tranco_db(lines, path: Path = TRANCO_DB) -> int:
    CACHE_DIR.mkdir(exist_ok=True)
    tmp = path.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    conn = sqlite3.connect(tmp)
    conn.executescript("CREATE TABLE tranco(domain TEXT PRIMARY KEY, rank INTEGER, sld TEXT, tld TEXT) WITHOUT ROWID;"
                       "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);")
    batch, count = [], 0
    for line in lines:
        line = line.strip()
        if not line or "," not in line:
            continue
        rank_s, domain = line.split(",", 1)
        if not rank_s.isdigit():
            continue
        rank, domain = int(rank_s), domain.strip().lower()
        sld = tld = None
        if rank <= 100000:                       # enrich only the top 100k (keeps build fast)
            ext = _TLDX(domain)
            sld, tld = ext.domain or None, (ext.suffix.split(".")[-1] if ext.suffix else None)
        batch.append((domain, rank, sld, tld))
        count += 1
        if len(batch) >= 50000:
            conn.executemany("INSERT OR REPLACE INTO tranco VALUES (?,?,?,?)", batch)
            batch.clear()
    if batch:
        conn.executemany("INSERT OR REPLACE INTO tranco VALUES (?,?,?,?)", batch)
    conn.execute("CREATE INDEX idx_rank ON tranco(rank)")
    conn.execute("CREATE INDEX idx_tld ON tranco(tld, rank)")
    conn.execute("INSERT INTO meta VALUES ('downloaded_at', ?)", (now_utc().isoformat(),))
    conn.execute("INSERT INTO meta VALUES ('rows', ?)", (str(count),))
    conn.commit()
    conn.close()
    os.replace(tmp, path)
    return count


def _csv_lines_from(fileobj_bytes: bytes):
    if fileobj_bytes[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(fileobj_bytes))
        name = next(n for n in z.namelist() if n.lower().endswith(".csv"))
        return io.TextIOWrapper(z.open(name), encoding="utf-8")
    return io.StringIO(fileobj_bytes.decode("utf-8"))


def update_tranco(local_file: str = None, quiet=False) -> int:
    def say(m):
        if not quiet:
            sys.stderr.write(f"{B}[tranco]{X} {m}\n")
    if local_file:
        say(f"Building DB from {local_file} ...")
        data = Path(local_file).read_bytes()
    else:
        say(f"Downloading {TRANCO_URL} (one-time, ~20 MB) ...")
        r = requests.get(TRANCO_URL, timeout=90, headers={"User-Agent": "SOC-Domain-Risk/2.0"})
        r.raise_for_status()
        data = r.content
    n = build_tranco_db(_csv_lines_from(data))
    say(f"{G}Done: {n:,} domains indexed.{X}")
    return n


def tranco_api_rank(domain: str):
    """Last-resort per-domain API lookup (slow, rate-limited) when no local DB exists."""
    try:
        r = requests.get(f"https://tranco-list.eu/api/ranks/domain/{domain}", timeout=NET_TIMEOUT)
        if r.status_code == 200:
            ranks = r.json().get("ranks") or []
            if ranks:
                return ranks[0].get("rank")
    except Exception:
        pass
    return None


# =====================================================================
#  INDICATOR HELPERS
# =====================================================================
def ind(iid, tier, name, triggered, points, max_points, evidence, status="evaluated"):
    return {"id": iid, "tier": tier, "name": name, "triggered": bool(triggered),
            "points": int(points) if triggered else 0, "max_points": max_points,
            "status": status, "evidence": evidence}


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


_baseline_cache = {"loaded": False, "slds": [], "map": {}}


def get_baseline(store: TrancoStore):
    """Typosquat baseline = curated brands + Tranco top-N second-level labels."""
    if _baseline_cache["loaded"]:
        return _baseline_cache
    m = {}
    for b, officials in BRANDS.items():
        m.setdefault(b, f"{b} (protected brand)")
    for sld, dom in store.baseline(TYPO_BASELINE_TOP_N):
        if sld and len(sld) >= 5 and sld not in m:
            m[sld] = dom
    _baseline_cache.update(loaded=True, slds=list(m), map=m)
    return _baseline_cache


# =====================================================================
#  TIER 1  -  CRITICAL
# =====================================================================
def ind1_idn(ctx, store):
    name = "IDN Homoglyph Attack (xn-- prefix)"
    labels = ctx["host"].split(".")
    xn = [l for l in labels if l.startswith("xn--")]
    if not xn:
        return ind(1, 1, name, False, 0, 70, ["No internationalised (xn--) labels in the host"])
    ev = [f"Punycode label(s): {', '.join(xn)}", f"Rendered as: {ctx['unicode_host']}"]
    brands_sld = set(BRANDS) | {s for s, _ in store.baseline(TYPO_BASELINE_TOP_N)} if store.available else set(BRANDS)
    pts, hit = 0, False
    for l in labels[:-1] if len(labels) > 1 else labels:
        if not l.startswith("xn--"):
            continue
        u = decode_label(l)
        scripts = {script_of(c) for c in u if c.isalpha()}
        skel = skeleton(u)
        mixed = len(scripts) > 1
        matched = skel in brands_sld and skel != u and ctx["registrable"] not in OFFICIAL_ALL
        if matched:
            ev.append(f"Label '{u}' folds to '{skel}' = known brand/top domain (scripts: {', '.join(sorted(scripts))})")
            pts, hit = 70, True
        elif mixed:
            ev.append(f"Label '{u}' mixes scripts: {', '.join(sorted(scripts))} (classic homoglyph spoof)")
            pts, hit = max(pts, 60), True
        else:
            ev.append(f"Label '{u}' is single-script ({', '.join(sorted(scripts))}) and does not imitate a known brand")
    return ind(1, 1, name, hit, pts, 70, ev)


def ind2_stuffing(ctx):
    name = "Subdomain Brand Stuffing (right-to-left deception)"
    sub = ctx["subdomain"]
    if not sub:
        return ind(2, 1, name, False, 0, 70, ["No subdomain present"])
    toks, labels = tokens(sub), sub.split(".")
    ev, pts = [], 0
    for brand, officials in BRANDS.items():
        if ctx["registrable"] in officials or not brand_in_tokens(brand, toks):
            continue
        embedded = any(brand_in_tokens(brand, tokens(l)) and i + 1 < len(labels) and labels[i + 1] in COMMON_TLD_LABELS
                       for i, l in enumerate(labels))
        ev.append(f"Brand '{brand}' sits in the subdomain '{sub}' but the real domain is '{ctx['registrable']}'"
                  + ("  (looks like an embedded domain name)" if embedded else ""))
        pts = max(pts, 70 if embedded else 60)
    if not ev:
        return ind(2, 1, name, False, 0, 70, [f"No protected brand in subdomain '{sub}'"])
    return ind(2, 1, name, True, pts, 70, ev)


def ind3_combosquat(ctx):
    name = "Exact Brand + High-Risk Token Combosquatting"
    sld = ctx["sld"]
    toks = sld.split("-")
    ev, pts = [], 0
    for brand, officials in BRANDS.items():
        if ctx["registrable"] in officials:
            continue
        for i, t in enumerate(toks):
            if t == brand:
                near = [toks[j] for j in (i - 1, i + 1) if 0 <= j < len(toks) and toks[j] in RISK_KEYWORDS]
                if near:
                    ev.append(f"'{brand}' hyphen-joined with risk keyword '{near[0]}' in '{sld}'")
                    pts = max(pts, 60)
            else:
                for kw in RISK_KEYWORDS:
                    if t in (brand + kw, kw + brand):
                        ev.append(f"'{brand}' glued to risk keyword '{kw}' in '{t}' (no hyphen)")
                        pts = max(pts, 45)
    if not ev:
        return ind(3, 1, name, False, 0, 60, [f"No brand + risk-keyword combination in '{sld}'"])
    return ind(3, 1, name, True, pts, 60, ev)


# =====================================================================
#  TIER 2  -  HIGH  (structural part; NRD and certificate checks need network data)
# =====================================================================
def ind5_typosquat(ctx, store, rank):
    name = "Typosquatting (Levenshtein / Jaro-Winkler vs top brands)"
    sld, ev, pts = ctx["sld"], [], 0
    if rank and rank <= 100000:
        return ind(5, 2, name, False, 0, 35, [f"Domain itself is Tranco #{rank:,} - established site, not evaluated as a squat"])
    if not sld or ctx["registrable"] in OFFICIAL_ALL:
        return ind(5, 2, name, False, 0, 35, ["Official brand domain"])
    base = get_baseline(store)
    cands = {sld, sld.replace("-", "")}
    best = None
    for cand in cands:
        for b in base["slds"]:
            if abs(len(b) - len(cand)) > 2 or b == cand:
                continue
            d = Levenshtein.distance(cand, b, score_cutoff=2)
            if d <= 1 and len(b) >= 5 or d == 2 and len(b) >= 8:
                if best is None or d < best[0]:
                    best = (d, cand, b)
    if best:
        d, cand, b = best
        ev.append(f"'{cand}' is {d} edit(s) from '{b}' ({base['map'][b]})")
        pts = 35 if d == 1 else 25
    else:   # Jaro-Winkler near-miss
        for b in base["slds"]:
            if len(b) >= 6 and b != sld and abs(len(b) - len(sld)) <= 3:
                if JaroWinkler.similarity(sld, b, score_cutoff=0.93) >= 0.93:
                    ev.append(f"'{sld}' has Jaro-Winkler similarity >= 0.93 with '{b}' ({base['map'][b]})")
                    pts = 15
                    break
    # exact brand label on a non-official suffix (TLD swap), e.g. paypal.xyz
    exact = [b for b in BRANDS if b == sld and ctx["registrable"] not in BRANDS[b]]
    if exact:
        ev.append(f"Brand label '{sld}' registered under unofficial suffix '.{ctx['suffix']}' (official: {', '.join(BRANDS[exact[0]][:3])})")
        pts = max(pts, 30)
    if not ev:
        return ind(5, 2, name, False, 0, 35, [f"No close match to {len(base['slds']):,} baseline brand labels"])
    return ind(5, 2, name, True, pts, 35, ev)


# =====================================================================
#  TIER 3  -  MEDIUM  (structural)
# =====================================================================
def ind7_tld(ctx, store):
    name = "High-Risk / Untrusted TLD"
    tld = ctx["tld"]
    cnt = store.tld_count_top100k(tld)
    ev = [f"TLD: .{tld}" + (f"  |  domains in Tranco top-100k using it: {cnt}" if cnt is not None else "  |  Tranco not available")]
    if tld in HIGH_RISK_TLDS:
        pts = 16 + (4 if cnt is not None and cnt < 5 else 0)
        ev.append("TLD is on the high-abuse list" + (" and almost absent from the Tranco top-100k" if cnt is not None and cnt < 5 else ""))
        return ind(7, 3, name, True, pts, 20, ev)
    if cnt == 0 and len(tld) > 2:
        ev.append("Generic TLD never seen in Tranco top-100k (unproven TLD)")
        return ind(7, 3, name, True, 5, 20, ev)
    return ind(7, 3, name, False, 0, 20, ev + ["TLD not flagged"])


def ind8_entropy(ctx):
    name = "High String Entropy (DGA-like randomness)"
    sld = ctx["sld"]
    if sld.startswith("xn--"):
        return ind(8, 3, name, False, 0, 15, ["IDN label - entropy not applicable"], "n/a")
    core = sld.replace("-", "")
    L = len(core)
    if L < 8:
        return ind(8, 3, name, False, 0, 15, [f"'{sld}' is short ({L} chars) - entropy not meaningful"])
    H = shannon(core)
    digits = sum(c.isdigit() for c in core) / L
    vowels = sum(c in "aeiou" for c in core) / L
    run = max((len(m.group()) for m in re.finditer(r"[^aeiou0-9]+", core)), default=0)
    ev = [f"'{core}': Shannon entropy {H:.2f} bits/char, length {L}, digits {digits:.0%}, vowels {vowels:.0%}, longest consonant run {run}"]
    mixed = digits >= 0.2 and any(c.isalpha() for c in core)
    strong = H >= 3.6 and L >= 12 and (mixed or vowels <= 0.25 or run >= 5)
    mod = H >= 3.3 and L >= 8 and (mixed or vowels <= 0.2 or run >= 5)
    if strong:
        return ind(8, 3, name, True, 15, 15, ev + ["Very random-looking string"])
    if mod:
        return ind(8, 3, name, True, 10, 15, ev + ["Somewhat random-looking string"])
    return ind(8, 3, name, False, 0, 15, ev + ["Looks like natural language"])


def ind10_hyphens(ctx):
    name = "Excessive Hyphenation"
    sld = ctx["sld"]
    clean = sld[4:] if sld.startswith("xn--") else sld
    n = clean.count("-")
    host_n = sum((l[4:] if l.startswith("xn--") else l).count("-") for l in ctx["host"].split(".")[:-1])
    ev = [f"'{sld}' contains {n} hyphen(s)" + (f" ({host_n} across the whole host)" if host_n != n else "")]
    if n >= 4:
        return ind(10, 3, name, True, 15, 15, ev)
    if n >= 3:
        return ind(10, 3, name, True, 10, 15, ev)
    return ind(10, 3, name, False, 0, 15, ev)


# =====================================================================
#  NETWORK COLLECTORS  (each runs in its own thread)
# =====================================================================
def _resolver():
    r = dns.resolver.Resolver()
    r.timeout, r.lifetime = 2.0, 3.0
    return r


def collect_dns(host: str, geo: bool) -> dict:
    out = {"resolved_ips": [], "ttl_seconds": None, "name_servers": [], "hosting_telemetry": None, "dns_status": "ok"}
    try:
        ans = _resolver().resolve(host, "A")
        out["ttl_seconds"] = ans.rrset.ttl if getattr(ans, "rrset", None) is not None else None
        out["resolved_ips"] = [r.to_text() for r in ans]
    except dns.resolver.NXDOMAIN:
        out["dns_status"] = "nxdomain"
    except dns.resolver.NoAnswer:
        out["dns_status"] = "no_a_record"
    except Exception as e:
        out["dns_status"] = f"error:{type(e).__name__}"
    if geo and out["resolved_ips"]:
        ip = out["resolved_ips"][0]
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query",
                               timeout=NET_TIMEOUT)
            d = res.json() if res.status_code == 200 else {}
            if d.get("status") == "success":
                out["hosting_telemetry"] = {
                    "primary_hosting_ip": ip, "all_resolved_ips": out["resolved_ips"], "asn": d.get("as"),
                    "isp": d.get("isp"), "organization": d.get("org"), "country": d.get("country"),
                    "country_code": d.get("countryCode"), "region": d.get("regionName"), "city": d.get("city")}
        except Exception:
            pass
    return out


def collect_ns(registrable: str) -> list:
    try:
        return sorted(r.to_text().strip(".") for r in _resolver().resolve(registrable, "NS"))
    except Exception:
        return []


def _rdap_bootstrap_base(tld: str):
    try:
        fresh = RDAP_BOOTSTRAP_FILE.is_file() and (time.time() - RDAP_BOOTSTRAP_FILE.stat().st_mtime) < 7 * 86400
        if fresh:
            data = json.loads(RDAP_BOOTSTRAP_FILE.read_text("utf-8"))
        else:
            CACHE_DIR.mkdir(exist_ok=True)
            r = requests.get(RDAP_BOOTSTRAP_URL, timeout=NET_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            RDAP_BOOTSTRAP_FILE.write_text(json.dumps(data), "utf-8")
        for tlds, urls in data.get("services", []):
            if tld in tlds and urls:
                u = urls[0]
                return u if u.endswith("/") else u + "/"
    except Exception:
        if RDAP_BOOTSTRAP_FILE.is_file():
            try:
                for tlds, urls in json.loads(RDAP_BOOTSTRAP_FILE.read_text("utf-8")).get("services", []):
                    if tld in tlds and urls:
                        return urls[0] if urls[0].endswith("/") else urls[0] + "/"
            except Exception:
                pass
    return None


def _walk_entities(entities):
    for e in entities or []:
        yield e
        yield from _walk_entities(e.get("entities"))


def _vcard(e) -> dict:
    props = {}
    va = e.get("vcardArray") or []
    for item in (va[1] if len(va) > 1 else []):
        try:
            key, val = item[0], item[3]
        except (IndexError, TypeError):
            continue
        if isinstance(val, list):
            val = " ".join(str(v) for v in val if v)
        props.setdefault(key, []).append(str(val or "").strip())
    return props


def _is_redacted(text: str) -> bool:
    t = (text or "").lower()
    return any(m in t for m in PRIVACY_MARKERS)


def parse_rdap(docs: list) -> dict:
    """docs = [registry_json, optional registrar_json]. Returns legacy keys + extra analysis fields."""
    created = expires = None
    entities, remarks = [], []
    for d in docs:
        for ev in d.get("events", []) or []:
            act = str(ev.get("eventAction", "")).lower()
            if act in ("registration", "created", "creation") and not created:
                created = ev.get("eventDate")
            elif act in ("expiration", "expires") and not expires:
                expires = ev.get("eventDate")
        entities += list(_walk_entities(d.get("entities")))
        for rm in d.get("remarks", []) or []:
            remarks.append(" ".join(rm.get("description", []) or []))
    registrar = abuse = None
    registrant_texts, saw_registrant, registrant_fields = [], False, 0
    for e in entities:
        roles = [r.lower() for r in e.get("roles", [])]
        vc = _vcard(e)
        if "registrar" in roles and not registrar:
            registrar = (vc.get("fn") or [None])[0] or e.get("handle")
        if "abuse" in roles and not abuse and vc.get("email"):
            abuse = vc["email"][0]
        if "registrant" in roles:
            saw_registrant = True
            for key in ("fn", "org", "adr", "email", "tel"):
                for v in vc.get(key, []):
                    if v:
                        registrant_fields += 1
                        registrant_texts.append(v)

    def parse_dt(s):
        if not s:
            return None
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    c_dt, e_dt = parse_dt(created), parse_dt(expires)
    age = (now_utc() - c_dt).days if c_dt else None
    duration = (e_dt - c_dt).days if c_dt and e_dt else None

    redacted_hits = [t for t in registrant_texts if _is_redacted(t)]
    remark_redacted = any(_is_redacted(r) for r in remarks)
    if not saw_registrant:
        privacy = "unknown"
    elif registrant_texts and len(redacted_hits) == len(registrant_texts):
        privacy = "redacted"
    elif redacted_hits:
        privacy = "partial"
    elif not registrant_texts and remark_redacted:
        privacy = "redacted"
    elif not registrant_texts:
        privacy = "unknown"
    else:
        privacy = "disclosed"
    org = next((t for t in registrant_texts if t and not _is_redacted(t)), None)
    return {
        "creation_date": created[:10] if created else None,
        "expiration_date": expires[:10] if expires else None,
        "age_in_days": age,
        "sponsoring_registrar": registrar or "Privatized / Unknown",
        "abuse_contact_email": abuse or "Not Publicly Exposed",
        "registrant_org": org or ("Redacted for Privacy" if privacy in ("redacted", "partial") else "Not Publicly Exposed"),
        "registration_duration_days": duration,
        "registrant_privacy_state": privacy,
        "privacy_evidence": redacted_hits[:3],
    }


def collect_rdap(registrable: str, tld: str) -> dict:
    urls = []
    base = _rdap_bootstrap_base(tld)
    if base:
        urls.append(base + "domain/" + registrable)
    urls.append("https://rdap.org/domain/" + registrable)
    headers = {"User-Agent": "SOC-Domain-Risk/2.0", "Accept": "application/rdap+json"}
    last_err = "RDAP data unavailable"
    t_end = time.time() + 7.0                                   # total RDAP budget
    for url in urls:
        if time.time() >= t_end:
            break
        try:
            res = requests.get(url, timeout=min(NET_TIMEOUT, max(0.5, t_end - time.time())), headers=headers)
        except Exception as e:
            last_err = f"RDAP query failed: {type(e).__name__}"
            continue
        if res.status_code == 404:
            return {"error": "RDAP: domain not found (not registered?)", "registered": False}
        if res.status_code != 200:
            last_err = f"RDAP HTTP {res.status_code}"
            continue
        try:
            doc = res.json()
        except ValueError:
            continue
        docs = [doc]
        for link in doc.get("links", []) or []:                      # registrar RDAP holds the registrant block
            if link.get("rel") == "related" and "rdap" in str(link.get("type", "")) and "/domain/" in str(link.get("href", "")):
                try:
                    r2 = requests.get(link["href"], timeout=min(NET_TIMEOUT, max(0.5, t_end - time.time())), headers=headers)
                    if r2.status_code == 200:
                        docs.append(r2.json())
                except Exception:
                    pass
                break
        try:
            out = parse_rdap(docs)
            out["registered"] = True
            return out
        except Exception as e:
            last_err = f"RDAP parse error: {type(e).__name__}"
    return {"error": last_err}


EV_OID, OV_OID, DV_OID, IV_OID = "2.23.140.1.1", "2.23.140.1.2.2", "2.23.140.1.2.1", "2.23.140.1.2.3"


def parse_certificate(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)

    def attr(name, oid):
        a = name.get_attributes_for_oid(oid)
        return a[0].value if a else None
    issuer_org, issuer_cn = attr(cert.issuer, NameOID.ORGANIZATION_NAME), attr(cert.issuer, NameOID.COMMON_NAME)
    subj_org, subj_cn = attr(cert.subject, NameOID.ORGANIZATION_NAME), attr(cert.subject, NameOID.COMMON_NAME)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    try:
        policies = [p.policy_identifier.dotted_string for p in
                    cert.extensions.get_extension_for_class(x509.CertificatePolicies).value]
    except x509.ExtensionNotFound:
        policies = []
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    if EV_OID in policies:
        level = "EV"
    elif OV_OID in policies or (subj_org and DV_OID not in policies):
        level = "OV"
    elif IV_OID in policies:
        level = "IV"
    else:
        level = "DV"
    issuer_text = (issuer_org or issuer_cn or "Unknown Issuer")
    return {
        "ssl_active": True, "sha256_fingerprint": hashlib.sha256(der).hexdigest(), "issuer": issuer_text,
        "subject_alternative_names_count": len(sans), "san_domains": sans[:10],
        "validation_level": level, "subject_org": subj_org, "subject_cn": subj_cn,
        "not_before": nb.strftime("%Y-%m-%d"), "not_after": na.strftime("%Y-%m-%d"),
        "validity_days": (na - nb).days,
        "free_acme_ca": any(f in f"{issuer_org} {issuer_cn}".lower() for f in FREE_DV_ISSUERS),
        "_sans": sans,
    }


def collect_tls(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
        return parse_certificate(der)           # real parsing: CERT_NONE returns an EMPTY dict from getpeercert()
    except Exception as e:
        return {"ssl_active": False, "error": f"TLS Connection Failed: {e}"}


# =====================================================================
#  NETWORK-DEPENDENT INDICATORS
# =====================================================================
def ind4_nrd(rd):
    name = "Newly Registered Domain (NRD)"
    age = rd.get("age_in_days")
    if age is None:
        return ind(4, 2, name, False, 0, 40, [rd.get("error", "Creation date unavailable")], "unavailable")
    ev = [f"Created {rd['creation_date']} - {age} day(s) old"]
    if age < 7:
        return ind(4, 2, name, True, 40, 40, ev + ["Registered less than 7 days ago"])
    if age < 14:
        return ind(4, 2, name, True, 35, 40, ev + ["Registered less than 14 days ago"])
    if age < NRD_STRICT_DAYS:
        return ind(4, 2, name, True, 25, 40, ev + [f"Registered less than {NRD_STRICT_DAYS} days ago (strict window)"])
    return ind(4, 2, name, False, 0, 40, ev + ["Older than the NRD window"])


def ind6_ca(tls, brand_claim):
    name = "Certificate Authority Mismatch (brand on free DV cert)"
    if not tls.get("ssl_active"):
        return ind(6, 2, name, False, 0, 25, [tls.get("error", "No TLS certificate presented")], "unavailable")
    ev = [f"Issuer: {tls['issuer']} | validation: {tls['validation_level']} | valid {tls['not_before']} -> {tls['not_after']} ({tls['validity_days']} days)"]
    if not brand_claim:
        return ind(6, 2, name, False, 0, 25, ev + ["No brand impersonation indicators - a DV certificate alone is normal"])
    if tls["validation_level"] == "DV":
        free = tls["free_acme_ca"]
        ev.append(f"Domain imitates brand(s) {', '.join(sorted(brand_claim))} but uses a {'free/automated ' if free else ''}DV certificate (no verified organisation)")
        return ind(6, 2, name, True, 25 if free else 18, 25, ev)
    return ind(6, 2, name, False, 0, 25, ev + ["Certificate carries a validated organisation (OV/EV)"])


def ind9_san(tls, ctx):
    name = "Abnormal SAN Density"
    if not tls.get("ssl_active"):
        return ind(9, 3, name, False, 0, 18, ["No certificate to inspect"], "unavailable")
    sans = tls.get("_sans") or []
    regs = set()
    for s in sans:
        e = _TLDX(s.lstrip("*."))
        if e.domain and e.suffix:
            regs.add(f"{e.domain}.{e.suffix}")
    others = regs - {ctx["registrable"]}
    ev = [f"{len(sans)} SAN entries -> {len(regs)} distinct registrable domains"]
    if len(others) < 10:
        return ind(9, 3, name, False, 0, 18, ev + ["Below the density threshold (10 unrelated domains)"])
    target = ctx["sld"]
    look = 0
    for r in others:
        sld = r.split(".")[0]
        if (target and JaroWinkler.similarity(sld, target) >= 0.8) or \
           any(b in sld and r not in BRANDS[b] and len(b) >= 5 for b in BRANDS):
            look += 1
    ratio = look / len(others)
    shared_cdn = "cloudflare" in tls.get("issuer", "").lower() or any("cloudflaressl" in s for s in sans)
    ev.append(f"{look}/{len(others)} ({ratio:.0%}) of the other domains look like lookalikes of '{target}' or a protected brand")
    if shared_cdn:
        ev.append("Certificate looks like a shared CDN certificate - weight reduced")
    pts = 18 if ratio >= 0.5 else 12
    if shared_cdn:
        pts //= 2
    return ind(9, 3, name, True, pts, 18, ev + [f"Sample: {', '.join(sorted(others)[:5])}"])


def ind11_window(rd):
    name = "Minimum Registration Window (1 year)"
    d = rd.get("registration_duration_days")
    if d is None:
        return ind(11, 4, name, False, 0, 5, ["Creation/expiry dates unavailable"], "unavailable")
    ev = [f"Registered {rd['creation_date']} -> expires {rd['expiration_date']} = {d} days"]
    if 350 <= d <= 380:
        return ind(11, 4, name, True, 5, 5, ev + ["Exactly a 1-year term (legit corporations usually register 3-10 years)"])
    return ind(11, 4, name, False, 0, 5, ev)


def ind12_privacy(rd):
    name = "Total Registrant Privacy Redaction"
    st = rd.get("registrant_privacy_state")
    if st is None:
        return ind(12, 4, name, False, 0, 5, [rd.get("error", "No registrant data")], "unavailable")
    ev = [f"Registrant data state: {st}"] + [f"marker: {t[:60]}" for t in rd.get("privacy_evidence", [])]
    if st == "redacted":
        return ind(12, 4, name, True, 5, 5, ev + ["All registrant fields are hidden / proxied"])
    if st == "partial":
        return ind(12, 4, name, True, 2, 5, ev + ["Some registrant fields are hidden"])
    if st == "unknown":
        return ind(12, 4, name, False, 0, 5, ev + ["Registry exposes no registrant block - cannot judge"], "unavailable")
    return ind(12, 4, name, False, 0, 5, ev + ["Registrant details are published"])


# =====================================================================
#  SCORE COMBINATION
# =====================================================================
def combine(indicators, rank, store_available):
    tiers = {1: 0, 2: 0, 3: 0, 4: 0}
    supp = 0
    for i in indicators:
        if i["triggered"]:
            if i["tier"] in tiers:
                tiers[i["tier"]] += i["points"]
            else:
                supp += i["points"]
    if rank is None:
        adj, adj_note = (5, "Not in the Tranco top-1M (+5)") if store_available else (0, "Tranco unavailable (no adjustment)")
    elif rank <= 10000:
        adj, adj_note = -15, f"Tranco #{rank:,} - top 10k (-15)"
    elif rank <= 100000:
        adj, adj_note = -10, f"Tranco #{rank:,} - top 100k (-10)"
    else:
        adj, adj_note = -4, f"Tranco #{rank:,} - top 1M (-4)"
    raw = sum(tiers.values()) + supp + adj
    total = max(0, min(100, raw))
    floor = False
    if any(i["triggered"] and i["tier"] == 1 for i in indicators) and total < T1_FLOOR:
        total, floor = T1_FLOOR, True
    level = next(name for thr, name in LEVELS if total >= thr)
    hit_tiers = [t for t in (1, 2, 3, 4) if any(i["triggered"] and i["tier"] == t for i in indicators)]
    top = hit_tiers[0] if hit_tiers else None
    conf = {1: "95%+", 2: "75-90%", 3: "40-70%", 4: "10-35%"}.get(top, "n/a")
    return {
        "score": total, "raw_score": raw, "risk_level": level,
        "verdict": {"LOW": "safe", "MEDIUM": "suspicious"}.get(level, "malicious"),
        "highest_tier_triggered": top, "confidence_band": conf, "tier1_floor_applied": floor,
        "tier_scores": {f"tier{t}": {"points": tiers[t], "triggered": sum(1 for i in indicators if i["tier"] == t and i["triggered"]),
                                      "label": TIER_INFO[t][0]} for t in tiers},
        "supplementary_points": supp, "tranco_adjustment": adj, "tranco_adjustment_note": adj_note,
    }


RECOMMENDATIONS = {
    "CRITICAL": "BLOCK. Active deception detected - treat as phishing, quarantine and investigate the sender/campaign.",
    "HIGH": "Likely malicious. Block or quarantine; confirm with sandbox/URL reputation before release.",
    "MEDIUM": "Suspicious. Hold for review and corroborate with URL/attachment/header analysis.",
    "LOW": "No meaningful phishing indicators. Normal handling.",
}


# =====================================================================
#  VALIDATED-DOMAIN CACHE  (logs/validated_domains.log, JSON lines)
# =====================================================================
class ValidatedCache:
    def __init__(self, path: Path):
        self.path, self.lock, self.records = path, threading.Lock(), {}
        LOG_DIR.mkdir(exist_ok=True)
        path.touch(exist_ok=True)
        for line in path.read_text("utf-8", errors="ignore").splitlines():
            try:
                rec = json.loads(line)
                self.records[rec["domain"]] = rec        # later lines win
            except (ValueError, KeyError):
                continue

    def get(self, host):
        rec = self.records.get(host)
        if not rec:
            return None
        try:
            if datetime.fromisoformat(rec["valid_until"]) > now_utc():
                return rec
        except ValueError:
            pass
        return None

    def put(self, result):
        ra = result["risk_assessment"]
        ttl = TTL_DEGRADED if result["analysis_meta"]["degraded"] else TTL_BY_LEVEL[ra["risk_level"]]
        rec = {"domain": result["target_domain"], "registrable": result["registrable_domain"],
               "analyzed_at": now_utc().isoformat(timespec="seconds"),
               "valid_until": (now_utc() + ttl).isoformat(timespec="seconds"),
               "score": ra["score"], "risk_level": ra["risk_level"], "verdict": ra["verdict"],
               "degraded": result["analysis_meta"]["degraded"], "result": result}
        with self.lock:
            self.records[rec["domain"]] = rec
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


# =====================================================================
#  ORCHESTRATION
# =====================================================================
def analyze_full(target: str, use_cache=True, refresh=False, geo=True) -> dict:
    t0 = time.perf_counter()
    host = extract_apex_domain(target)
    if not host:
        return {"target_domain": target, "error": "Could not extract a hostname from input"}

    cache = ValidatedCache(VALIDATED_LOG) if use_cache else None
    if cache and not refresh:
        rec = cache.get(host)
        if rec:
            res = json.loads(json.dumps(rec["result"]))
            res["analysis_meta"].update(cache={"hit": True, "analyzed_at": rec["analyzed_at"], "valid_until": rec["valid_until"]},
                                        elapsed_ms=int((time.perf_counter() - t0) * 1000))
            return res

    ctx = build_context(host)
    store = TrancoStore(TRANCO_DB)
    if not store.available and not ctx["is_ip"]:
        try:
            update_tranco()                       # one-time automatic download
            store = TrancoStore(TRANCO_DB)
        except Exception as e:
            sys.stderr.write(f"[!] Tranco list unavailable ({type(e).__name__}); using API fallback + curated brands only\n")
    if ctx["is_ip"]:
        rank = None
    else:
        rank = store.rank(ctx["registrable"]) if store.available else tranco_api_rank(ctx["registrable"])

    # ---------------- IP literal short-circuit ----------------
    if ctx["is_ip"]:
        dns_res = collect_dns_ip(host, geo)
        indicators = [ind("S4", "S", "Raw IP address used as host", True, 20, 20, ["URL uses a bare IP instead of a domain name"])]
        score = combine(indicators, None, False)
        return finish(ctx, store, rank, indicators, score, dns_res, {"error": "n/a for IP host"}, {"ssl_active": False, "error": "skipped"},
                      [], t0, cache, fast=False, degraded=False)

    # ---------------- structural indicators (instant) ----------------
    i1 = ind1_idn(ctx, store)
    i2 = ind2_stuffing(ctx)
    i3 = ind3_combosquat(ctx)
    i5 = ind5_typosquat(ctx, store, rank)
    i7 = ind7_tld(ctx, store)
    i8 = ind8_entropy(ctx)
    i10 = ind10_hyphens(ctx)
    struct_alarm = any(i["triggered"] for i in (i1, i2, i3, i5))
    brand_claim = set()
    for i in (i1, i2, i3, i5):
        if i["triggered"]:
            brand_claim.update(re.findall(r"'([a-z0-9]+)'", " ".join(i["evidence"])) or ["brand"])
    brand_claim = {b for b in brand_claim if b in BRANDS} or ({"brand"} if struct_alarm else set())

    fast = bool(FAST_TRUST_RANK and rank and rank <= FAST_TRUST_RANK and not struct_alarm)

    # ---------------- parallel network phase ----------------
    if fast:
        dns_res = {"resolved_ips": [], "ttl_seconds": None, "name_servers": [], "hosting_telemetry": None, "dns_status": "skipped"}
        rd, tls, ns = {"error": "skipped (trusted Tranco fast-path)"}, {"ssl_active": False, "error": "skipped (trusted Tranco fast-path)"}, []
    else:
        ex = ThreadPoolExecutor(max_workers=4)
        f_dns = ex.submit(collect_dns, host, geo)
        f_ns = ex.submit(collect_ns, ctx["registrable"])
        f_rd = ex.submit(collect_rdap, ctx["registrable"], ctx["tld"])
        f_tls = ex.submit(collect_tls, host)
        deadline = time.perf_counter() + OVERALL_DEADLINE

        def get(f, default):
            try:
                return f.result(timeout=max(0.1, deadline - time.perf_counter()))
            except Exception as e:
                return default(e)
        dns_res = get(f_dns, lambda e: {"resolved_ips": [], "ttl_seconds": None, "name_servers": [], "hosting_telemetry": None, "dns_status": "timeout"})
        ns = get(f_ns, lambda e: [])
        rd = get(f_rd, lambda e: {"error": f"RDAP timeout ({type(e).__name__})"})
        tls = get(f_tls, lambda e: {"ssl_active": False, "error": f"TLS timeout ({type(e).__name__})"})
        ex.shutdown(wait=False, cancel_futures=True)      # never block on a slow lookup

    # ---------------- network-dependent indicators ----------------
    i4, i6, i9 = ind4_nrd(rd), ind6_ca(tls, brand_claim), ind9_san(tls, ctx)
    i11, i12 = ind11_window(rd), ind12_privacy(rd)
    indicators = [i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12]

    age = rd.get("age_in_days")
    unranked = rank is None and store.available
    indicators.append(ind("S1", "S", "Unranked domain (not in Tranco top-1M)", unranked, 5, 5,
                          ["Not present in the Tranco top-1M list" if unranked else
                           (f"Tranco rank #{rank:,}" if rank else "Tranco unavailable")]))
    rdap_down = bool(rd.get("error")) and rd.get("registered") is not False and not fast
    indicators.append(ind("S2", "S", "Registration data unavailable", rdap_down, 3, 3, [rd.get("error", "RDAP ok")]))
    young = age is not None and NRD_STRICT_DAYS <= age < 90
    indicators.append(ind("S3", "S", "Young domain (30-90 days)", young, 6, 6,
                          [f"{age} days old" if age is not None else "Age unknown"]))

    score = combine(indicators, rank, store.available)
    degraded = (rdap_down and not fast) or not store.available
    return finish(ctx, store, rank, indicators, score, dns_res, rd, tls, ns, t0, cache, fast, degraded)


def collect_dns_ip(ip, geo):
    out = {"resolved_ips": [ip], "ttl_seconds": None, "name_servers": [], "hosting_telemetry": None, "dns_status": "ip_literal"}
    if geo:
        try:
            d = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as", timeout=NET_TIMEOUT).json()
            if d.get("status") == "success":
                out["hosting_telemetry"] = {"primary_hosting_ip": ip, "all_resolved_ips": [ip], "asn": d.get("as"), "isp": d.get("isp"),
                                            "organization": d.get("org"), "country": d.get("country"), "country_code": d.get("countryCode"),
                                            "region": d.get("regionName"), "city": d.get("city")}
        except Exception:
            pass
    return out


def finish(ctx, store, rank, indicators, score, dns_res, rd, tls, ns, t0, cache, fast, degraded):
    tls = dict(tls)
    tls.pop("_sans", None)
    dns_res = dict(dns_res)
    dns_res["name_servers"] = ns
    triggered = [f"T{i['tier']}:{i['name']}" if i["tier"] != "S" else f"S:{i['name']}" for i in indicators if i["triggered"]]
    tr = {"available": store.available, "tranco_found": rank is not None, "tranco_rank": rank,
          "is_safelisted": bool(rank and rank <= 100000), "list_age_days": store.age_days(),
          "tld_in_top100k_count": store.tld_count_top100k(ctx["tld"]) if store.available else None}
    result = {
        "target_domain": ctx["host"],
        "registrable_domain": ctx["registrable"],
        "unicode_domain": ctx["unicode_host"],
        "infrastructure_and_hosting": dns_res,
        "lifecycle_and_attribution": rd,
        "cryptographic_tokens": tls,
        "tranco_telemetry": tr,
        "risk_assessment": {**score, "indicators": indicators, "triggered_flags": triggered,
                            "recommendation": RECOMMENDATIONS[score["risk_level"]]},
        "analysis_meta": {"elapsed_ms": int((time.perf_counter() - t0) * 1000), "fast_path": fast, "degraded": degraded,
                          "cache": {"hit": False}, "engine": "domain_risk_analyzer/2.0"},
    }
    if cache:
        cache.put(result)
    return result


# =====================================================================
#  BACKWARD-COMPATIBLE WRAPPERS  (so email_data_extractor1.py keeps working)
# =====================================================================
def extract_deep_intelligence(target: str) -> dict:
    """Old domain_intel_analyzer API: same keys (infrastructure_and_hosting / lifecycle_and_attribution /
    cryptographic_tokens) + new risk_assessment."""
    return analyze_full(target)


def analyze_domain(target: str) -> dict:
    """Old Domain_Analyzer API shape."""
    r = analyze_full(target)
    if "risk_assessment" not in r:
        return r
    ra, tr, rd = r["risk_assessment"], r["tranco_telemetry"], r["lifecycle_and_attribution"]
    return {
        "target_domain": r["target_domain"], "overall_risk_level": ra["risk_level"],
        "risk_status": ra["triggered_flags"][0] if ra["triggered_flags"] else "NO_INDICATORS",
        "tranco_telemetry": {"tranco_found": tr["tranco_found"], "tranco_rank": tr["tranco_rank"], "is_safelisted": tr["is_safelisted"]},
        "rdap_telemetry": {"rdap_success": "error" not in rd, "creation_date": rd.get("creation_date"),
                           "age_in_days": rd.get("age_in_days"),
                           "is_newly_registered": (rd.get("age_in_days") < NRD_STRICT_DAYS) if rd.get("age_in_days") is not None else None},
        "investigation_recommendation": ra["recommendation"],
        "requires_deep_inspection": ra["risk_level"] != "LOW",
        "risk_score": ra["score"],
    }


# =====================================================================
#  HUMAN REPORT
# =====================================================================
def render_report(r: dict, out=sys.stdout):
    if "risk_assessment" not in r:
        print(f"{R}{r.get('error', 'analysis failed')}{X}", file=out)
        return
    P = lambda s="": print(s, file=out)
    ra, tr, meta = r["risk_assessment"], r["tranco_telemetry"], r["analysis_meta"]
    lvl_col = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": G}[ra["risk_level"]]
    tier_col = {1: R, 2: R, 3: Y, 4: B, "S": C}
    bar = "═" * 70

    P(f"\n{B}{BOLD}  ╔{bar}╗")
    P(f"  ║{'DOMAIN RISK ANALYZER  ·  4-tier phishing-domain scoring':^70}║")
    P(f"  ╚{bar}╝{X}")
    P(f"{W}  Target      : {BOLD}{r['target_domain']}{X}{W}" + (f"   (renders as: {r['unicode_domain']})" if r['unicode_domain'] != r['target_domain'] else ""))
    P(f"  Registrable : {r['registrable_domain']}")
    rank_txt = f"#{tr['tranco_rank']:,}" if tr["tranco_rank"] else ("unranked" if tr["available"] else "Tranco unavailable")
    P(f"  Tranco      : {rank_txt}" + (f"   (list age {tr['list_age_days']}d)" if tr['list_age_days'] is not None else "") + X)

    P(f"\n{lvl_col}{BOLD}  ╔{bar}╗")
    inner = f"  VERDICT: {ra['risk_level']} · {ra['score']}/100 · {ra['verdict'].upper()} · confidence {ra['confidence_band']}"
    P(f"  ║{inner:<70}║")
    P(f"  ╚{bar}╝{X}")

    for t in (1, 2, 3, 4):
        ts = ra["tier_scores"][f"tier{t}"]
        P(f"\n{tier_col[t]}{BOLD}  ━━ {TIER_INFO[t][0]}  ·  {TIER_INFO[t][1]}   [tier points: {ts['points']}]{X}")
        for i in [x for x in ra["indicators"] if x["tier"] == t]:
            if i["status"] == "unavailable":
                mark, col = "?", GRAY
            elif i["triggered"]:
                mark, col = "✖", tier_col[t]
            else:
                mark, col = "✔", G
            pts = f"+{i['points']}" if i["triggered"] else "  0"
            P(f"  {col}{mark} {i['id']:>2}. {i['name']:<58}{pts:>4}  /{i['max_points']}{X}")
            for e in i["evidence"]:
                P(f"{GRAY}        └ {e}{X}")

    supp = [x for x in ra["indicators"] if x["tier"] == "S"]
    P(f"\n{C}{BOLD}  ━━ SUPPLEMENTARY CONTEXT  (Tranco / data-availability){X}")
    for i in supp:
        col, mark = (C, "✖") if i["triggered"] else (G, "✔")
        P(f"  {col}{mark} {i['id']:>3}  {i['name']:<57}{('+' + str(i['points'])) if i['triggered'] else '  0':>4}{X}")
        for e in i["evidence"]:
            P(f"{GRAY}        └ {e}{X}")
    P(f"  {W}Tranco trust adjustment: {ra['tranco_adjustment']:+d}  ({ra['tranco_adjustment_note']}){X}")

    inf, lc, tls = r["infrastructure_and_hosting"], r["lifecycle_and_attribution"], r["cryptographic_tokens"]
    P(f"\n{B}{BOLD}  ━━ EVIDENCE COLLECTED{X}")
    ht = inf.get("hosting_telemetry") or {}
    P(f"{W}  DNS      : {', '.join(inf.get('resolved_ips') or []) or inf.get('dns_status', 'n/a')}   TTL {inf.get('ttl_seconds')}")
    P(f"  NS       : {', '.join(inf.get('name_servers') or []) or 'n/a'}")
    P(f"  Hosting  : {ht.get('asn', 'n/a')}  ·  {ht.get('country', 'n/a')} {ht.get('city') or ''}")
    if "error" in lc:
        P(f"  Registry : {lc['error']}")
    else:
        P(f"  Registry : created {lc.get('creation_date')} ({lc.get('age_in_days')}d)  expires {lc.get('expiration_date')}  registrar {lc.get('sponsoring_registrar')}")
        P(f"  Registrant: {lc.get('registrant_org')}  (privacy: {lc.get('registrant_privacy_state')})")
    if tls.get("ssl_active"):
        P(f"  TLS      : {tls['issuer']} · {tls['validation_level']} · {tls['validity_days']}d validity · {tls['subject_alternative_names_count']} SAN(s)")
    else:
        P(f"  TLS      : {tls.get('error', 'n/a')}")
    P(X)

    P(f"{W}{BOLD}  ━━ SCORE BREAKDOWN{X}")
    ts_ = ra["tier_scores"]
    P(f"{W}  Tier1 {ts_['tier1']['points']}  +  Tier2 {ts_['tier2']['points']}  +  Tier3 {ts_['tier3']['points']}  +  Tier4 {ts_['tier4']['points']}"
      f"  +  Supplementary {ra['supplementary_points']}  +  Tranco {ra['tranco_adjustment']:+d}  =  {ra['raw_score']}  (capped 0-100)")
    if ra["tier1_floor_applied"]:
        P(f"{R}  Tier-1 rule: any critical indicator forces the score to at least {T1_FLOOR}.{X}")
    P(f"\n{lvl_col}{BOLD}  ➜ {ra['recommendation']}{X}")
    cache = meta["cache"]
    P(f"{GRAY}  [{meta['elapsed_ms']} ms · {'CACHE HIT (analysed ' + cache['analyzed_at'] + ')' if cache.get('hit') else 'fresh analysis'}"
      f"{' · fast-path' if meta['fast_path'] else ''}{' · DEGRADED data' if meta['degraded'] else ''}]{X}\n")


def list_cache():
    cache = ValidatedCache(VALIDATED_LOG)
    print(f"{B}{BOLD}Validated domains ({len(cache.records)}) - {VALIDATED_LOG}{X}")
    for d, rec in sorted(cache.records.items(), key=lambda kv: kv[1]["analyzed_at"], reverse=True):
        col = {"CRITICAL": R, "HIGH": R, "MEDIUM": Y, "LOW": G}[rec["risk_level"]]
        live = "valid" if cache.get(d) else "expired"
        print(f"  {col}{rec['risk_level']:<8}{X} {rec['score']:>3}  {d:<45} {GRAY}{rec['analyzed_at']}  ({live}){X}")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="4-tier domain risk analyzer")
    ap.add_argument("target", nargs="?", help="domain or URL")
    ap.add_argument("--report", action="store_true", help="human-readable colored report")
    ap.add_argument("--json", action="store_true", help="also/only print JSON")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--refresh", action="store_true", help="ignore cached verdict and re-analyse")
    ap.add_argument("--no-geo", action="store_true", help="skip ip-api.com enrichment")
    ap.add_argument("--update-tranco", action="store_true")
    ap.add_argument("--tranco-file", help="build the Tranco DB from a local csv/zip")
    ap.add_argument("--list-cache", action="store_true")
    a = ap.parse_args()

    if a.tranco_file:
        update_tranco(a.tranco_file)
        if not a.target:
            return
    if a.update_tranco:
        update_tranco()
        if not a.target:
            return
    if a.list_cache:
        list_cache()
        return
    if not a.target:
        ap.print_help()
        sys.exit(1)

    res = analyze_full(a.target, use_cache=not a.no_cache, refresh=a.refresh, geo=not a.no_geo)
    if a.report and a.json:
        render_report(res, out=sys.stderr)
        print(json.dumps(res, indent=2, ensure_ascii=False))
    elif a.report:
        render_report(res)
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
