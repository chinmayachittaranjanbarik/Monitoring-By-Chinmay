#!/usr/bin/env python3
"""
monitor_backend.py — ORSAC monitor (final polished backend)

Features:
- Phase-by-phase HTTP timings (DNS, TCP, TLS, HTTP TTFB, HTTP FirstChunk, HTTP Total)
- Redirect counts and per-redirect TTFB times
- Immediate CSV logging with header ensured and fsync to disk
- Retries and external verification (DNS + HTTP) to reduce false positives
- **PASSIVE KEYWORD CHECK: Records content status but does NOT affect site UP/DOWN status or alerting.**
- CLI modes: --run-now (one-shot), --diag <url> (diagnostic)
- Configurable via .env and sites.yaml
"""

import os
import csv
import time
import ssl
import socket
import logging
import sys
import json
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote
from contextlib import closing
import warnings

from dateutil import parser as dateutil_parser
from dateutil import tz as dateutil_tz

# Optional libs & Lock imports
HAS_REQUESTS = False
HAS_ICMPLIB = False
HAS_DNS = False

from filelock import FileLock
from dotenv import dotenv_values

# FIX: Cleaned and restructured import blocks to remove U+00A0 errors
try:
    import requests
    from requests.exceptions import RequestException, Timeout as RequestsTimeout
    HAS_REQUESTS = True
except Exception:
    print("WARNING: requests not available; HTTP checks will be skipped or limited.")

try:
    import icmplib
    HAS_ICMPLIB = True
except Exception:
    print("WARNING: icmplib not available; ICMP ping skipped.")

try:
    import dns.resolver
    HAS_DNS = True
except Exception:
    print("WARNING: dnspython not available; DNS resolver probes limited.")

# ---------------------------
# Load env defaults
# ---------------------------
# FIX: Cleaned U+00A0 error from this block
try:
    for k, v in dotenv_values().items():
        if k and v is not None:
            os.environ.setdefault(k, str(v))
except Exception:
    pass

CONFIG_FILE = os.getenv("SITES_YAML", "sites.yaml")
LOG_FILE = os.getenv("LOG_FILE", "website_monitor_log.csv")
LOCK_FILE = LOG_FILE + ".lock"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format="%(asctime)s - %(levelname)s - %(message)s")

MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", "1800"))
DEFAULT_TIMEOUT = float(os.getenv("DEFAULT_TIMEOUT", "10"))
DEFAULT_HTTP_CHECK_TIMEOUT = float(os.getenv("HTTP_CHECK_TIMEOUT", str(DEFAULT_TIMEOUT)))
USE_ICMP_BY_DEFAULT = os.getenv("USE_ICMP_BY_DEFAULT", "true").lower() in ("1", "true", "yes")
RETRY_ATTEMPTS = int(os.getenv("RETRY_ATTEMPTS", "2"))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", "3"))
EXTERNAL_DNS_SERVERS = [s.strip() for s in os.getenv("EXTERNAL_DNS_SERVERS", "8.8.8.8,1.1.1.1,9.9.9.9").split(",") if s.strip()]
EXTERNAL_HTTP_PROBES = [s.strip() for s in os.getenv("EXTERNAL_HTTP_PROBES", "DIRECT,https://api.allorigins.win/raw?url=").split(",") if s.strip()]
EXTERNAL_CHECK_TIMEOUT = int(os.getenv("EXTERNAL_CHECK_TIMEOUT", "10"))
VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() in ("1", "true", "yes")
FORCE_RUN_ON_START = os.getenv("FORCE_RUN_ON_START", "false").lower() in ("1", "true", "yes")
SSL_ALERT_DAYS = int(os.getenv("SSL_ALERT_DAYS", "30"))
RESPONSE_TIME_THRESHOLD = float(os.getenv("RESPONSE_TIME_THRESHOLD", "3000"))

# Email / alerts (optional — fill via .env)
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() in ("1", "true", "yes")
EMAIL_SMTP = os.getenv("EMAIL_SMTP", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", EMAIL_USER)
EMAIL_TO = [e.strip() for e in os.getenv("EMAIL_TO", "").split(",") if e.strip()]

ALERT_CONSECUTIVE_FAILURES = int(os.getenv("ALERT_CONSECUTIVE_FAILURES", "3"))
ALERT_MINUTES_DOWN = int(os.getenv("ALERT_MINUTES_DOWN", "5"))
SITE_STATE_FILE = os.getenv("SITE_STATE_FILE", "site_state.json")
SITE_STATE_LOCK = SITE_STATE_FILE + ".lock"

# ---------------------------
# Load sites.yaml
# ---------------------------
# FIX: Cleaned and properly structured error handling for YAML loading
try:
    import yaml
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
except FileNotFoundError:
    logging.error("sites.yaml not found; exiting.")
    raise SystemExit(1)
except Exception as e:
    logging.error("Failed to load sites.yaml: %s", e)
    raise SystemExit(1)

sites = cfg.get("sites", []) or []
settings = cfg.get("settings", {}) or {}

# apply settings overrides (if present)
MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", settings.get("monitor_interval", MONITOR_INTERVAL)))
DEFAULT_TIMEOUT = float(os.getenv("DEFAULT_TIMEOUT", settings.get("default_timeout", DEFAULT_TIMEOUT)))
DEFAULT_HTTP_CHECK_TIMEOUT = float(os.getenv("HTTP_CHECK_TIMEOUT", settings.get("http_check_timeout", DEFAULT_HTTP_CHECK_TIMEOUT)))
RETRY_ATTEMPTS = int(os.getenv("RETRY_ATTEMPTS", settings.get("retry_attempts", RETRY_ATTEMPTS)))
RETRY_DELAY = int(os.getenv("RETRY_DELAY", settings.get("retry_delay", RETRY_DELAY)))
RESPONSE_TIME_THRESHOLD = float(os.getenv("RESPONSE_TIME_THRESHOLD", settings.get("response_time_threshold", RESPONSE_TIME_THRESHOLD)))

# ---------------------------
# HTTP session
# ---------------------------
# FIX: Cleaned U+00A0 error from this block
HTTP_SESSION = None
if HAS_REQUESTS:
    HTTP_SESSION = requests.Session()
    HTTP_SESSION.headers.update({"User-Agent": "ORSAC-Monitor/1.0"})
    HTTP_SESSION.verify = VERIFY_SSL
    if not VERIFY_SSL:
        try:
            from urllib3.exceptions import InsecureRequestWarning
            warnings.filterwarnings("ignore", category=InsecureRequestWarning)
        except Exception:
            pass

# ---------------------------
# CSV header
# ---------------------------
# REINSTATED "Keyword Check" field
CSV_FIELDNAMES = [
    "DateTime", "Website Name", "URL", "Status",
    "Ping (ms)", "TCP Connect (ms)", "TLS Handshake (ms)",
    "DNS Time (ms)",
    "HTTP TTFB (ms)", "HTTP FirstChunk (ms)", "HTTP Total (ms)",
    "Redirects", "Redirect Times (ms)", "Content Size (KB)",
    "Keyword Check", "SSL Days Left", "SSL Expiry Date",
    "Probes Summary", "Notes"
]

def ensure_log_header():
    try:
        if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
            with FileLock(LOCK_FILE, timeout=10):
                with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
                    writer.writeheader()
                    f.flush(); os.fsync(f.fileno())
            logging.info("Created log file header.")
    except Exception:
        logging.exception("Could not ensure log header")

def write_log_rows(rows):
    if not rows:
        return
    try:
        with FileLock(LOCK_FILE, timeout=15):
            file_exists = os.path.exists(LOG_FILE)
            write_header = not file_exists or os.stat(LOG_FILE).st_size == 0
            with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
                if write_header:
                    writer.writeheader()
                for r in rows:
                    out = {}
                    for k in CSV_FIELDNAMES:
                        v = r.get(k, "")
                        if isinstance(v, (dict, list)):
                            out[k] = json.dumps(v, default=str)
                        else:
                            out[k] = "" if v is None else str(v)
                    writer.writerow(out)
                f.flush(); os.fsync(f.fileno())
    except Exception:
        logging.exception("Failed to write logs")

ensure_log_header()

# ---------------------------
# site state persistence
# ---------------------------
def load_site_state():
    if not os.path.exists(SITE_STATE_FILE):
        return {}
    try:
        with FileLock(SITE_STATE_LOCK, timeout=5):
            with open(SITE_STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        try:
            with open(SITE_STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

def save_site_state(state):
    try:
        with FileLock(SITE_STATE_LOCK, timeout=5):
            with open(SITE_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, default=str)
    except Exception:
        logging.exception("Failed to save site state")

site_state = load_site_state()

# ---------------------------
# helpers & external probes
# ---------------------------
def get_hostname(url_or_host):
    try:
        parsed = urlparse(url_or_host)
        host = parsed.hostname or parsed.path
        host = host.split('@')[-1].split(':')[0].strip()
        return host.encode('idna').decode('ascii')
    except Exception:
        return url_or_host

def probe_external_dns(hostname, nameserver, timeout=5):
    if not hostname or not HAS_DNS:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.lifetime = timeout
        answers = resolver.resolve(hostname, "A", lifetime=timeout)
        return bool(answers)
    except Exception:
        return False

def probe_external_http(url, probe_prefix, timeout=EXTERNAL_CHECK_TIMEOUT):
    if not HAS_REQUESTS or not url or not HTTP_SESSION:
        return False
    try:
        prefix = probe_prefix.strip()
        if prefix.upper() == "DIRECT":
            r = HTTP_SESSION.get(url, timeout=timeout, allow_redirects=True, verify=VERIFY_SSL, stream=True)
        else:
            if "{url}" in prefix:
                probe_url = prefix.format(url=quote(url, safe=''))
            else:
                probe_url = prefix + quote(url, safe='')
            r = HTTP_SESSION.get(probe_url, timeout=timeout, allow_redirects=True, verify=VERIFY_SSL, stream=True)
        ok = 200 <= r.status_code < 400
        try: r.close()
        except: pass
        return ok
    except Exception:
        return False

# ---------------------------
# Measurement: phase-by-phase HTTP timings
# ---------------------------
def measure_http_phases(url, timeout=DEFAULT_HTTP_CHECK_TIMEOUT, max_first_bytes=65536):
    out = {
        "dns_ms": None,
        "tcp_ms": None,
        "tls_ms": None,
        "ttfb_ms": None,
        "first_chunk_ms": None,
        "total_transfer_ms": None,
        "redirects": 0,
        "redirect_times_ms": [],
        "status_code": None,
        "content_length": None
    }

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme.lower()

    # DNS
    try:
        t0 = time.perf_counter()
        if HAS_DNS:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = min(3, timeout)
            answers = resolver.resolve(hostname, "A", lifetime=min(3, timeout))
            ip = answers[0].to_text() if answers else None
        else:
            addrs = socket.getaddrinfo(hostname, None)
            ip = addrs[0][4][0] if addrs else None
        out["dns_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        out["dns_ms"] = None
        ip = None

    # TCP connect
    try:
        t0 = time.perf_counter()
        with closing(socket.create_connection((hostname, port), timeout=min(timeout, 10))):
            out["tcp_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    except Exception:
        out["tcp_ms"] = None

    # TLS handshake
    if scheme == "https":
        try:
            ctx = ssl.create_default_context()
            t0 = time.perf_counter()
            with closing(socket.create_connection((hostname, 443), timeout=min(timeout, 10))) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    out["tls_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        except Exception:
            out["tls_ms"] = None

    # requests measurement (TTFB, first chunk, total chunk) - follow redirects manually
    if not HAS_REQUESTS or not HTTP_SESSION:
        return out

    try:
        def _measure_hop(target_url, timeout_hop=timeout):
            hop = {"ttfb": None, "first_chunk": None, "total_chunk": None, "status": None, "content_length": None}
            try:
                s = time.perf_counter()
                r = HTTP_SESSION.get(target_url, timeout=timeout_hop, allow_redirects=False, verify=VERIFY_SSL, stream=True)
                ttfb = (time.perf_counter() - s) * 1000.0
                hop["ttfb"] = round(ttfb, 2)
                hop["status"] = int(r.status_code) if r.status_code is not None else None
                hop["content_length"] = r.headers.get("Content-Length")
                try:
                    s2 = time.perf_counter()
                    chunk = next(r.iter_content(chunk_size=16384), b"")
                    hop["first_chunk"] = round((time.perf_counter() - s2) * 1000.0, 2)
                    total_read = len(chunk) if chunk else 0
                    start_total = time.perf_counter()
                    while total_read < max_first_bytes:
                        nxt = next(r.iter_content(chunk_size=16384), b"")
                        if not nxt:
                            break
                        total_read += len(nxt)
                    hop["total_chunk"] = round((time.perf_counter() - start_total) * 1000.0, 2) if total_read > 0 else 0.0
                except StopIteration:
                    hop["first_chunk"] = 0.0
                    hop["total_chunk"] = 0.0
                except Exception:
                    pass 
                
                try: r.close()
                except Exception: pass
            except RequestsTimeout:
                hop["ttfb"] = None; hop["status"] = None
            except RequestException:
                hop["ttfb"] = None; hop["status"] = None
            except Exception:
                hop["ttfb"] = None; hop["status"] = None
            return hop

        MAX_REDIRECTS = 6
        cur_url = url
        redirect_times = []
        redirects = 0
        last_hop = None
        for hop_i in range(MAX_REDIRECTS):
            hop = _measure_hop(cur_url, timeout_hop=timeout)
            last_hop = hop
            if hop["ttfb"] is not None:
                if hop_i == 0:
                    out["ttfb_ms"] = hop["ttfb"]
                    out["first_chunk_ms"] = hop.get("first_chunk")
                    out["total_transfer_ms"] = hop.get("total_chunk")
                    out["status_code"] = hop.get("status")
                    out["content_length"] = hop.get("content_length")
                else:
                    redirect_times.append(hop["ttfb"])
            status = hop.get("status") or 0
            if 300 <= status < 400 and hop_i < MAX_REDIRECTS - 1:
                try:
                    r = HTTP_SESSION.get(cur_url, timeout=min(5, timeout), allow_redirects=False, verify=VERIFY_SSL, stream=True)
                    loc = r.headers.get("Location") or r.headers.get("location")
                    try: r.close()
                    except: pass
                    if not loc:
                        break
                    cur_url = urljoin(cur_url, loc)
                    redirects += 1
                    continue
                except Exception:
                    break
            else:
                break

        out["redirects"] = redirects
        out["redirect_times_ms"] = [round(float(x), 2) for x in redirect_times]
        if out["ttfb_ms"] is None and last_hop:
            out["ttfb_ms"] = last_hop.get("ttfb")
            out["first_chunk_ms"] = last_hop.get("first_chunk")
            out["total_transfer_ms"] = last_hop.get("total_chunk")
            out["status_code"] = last_hop.get("status")
            out["content_length"] = last_hop.get("content_length")
    except Exception:
        logging.exception("HTTP phase measurement failed for %s", url)

    return out

# ---------------------------
# Core site check (single-run)
# ---------------------------
def check_site_core(site):
    name = site.get("name") or site.get("Website") or site.get("url") or "Unnamed"
    url = (site.get("url") or site.get("URL") or "").strip()
    timeout = float(site.get("timeout", DEFAULT_TIMEOUT))
    http_timeout = float(site.get("http_check_timeout", DEFAULT_HTTP_CHECK_TIMEOUT))
    expected_status = site.get("expected_status", 200)
    try:
        expected_status = int(expected_status)
    except Exception:
        expected_status = 200
    
    # KEYWORD CHECK: Restore keyword variables for use in passive logging
    keyword = site.get("keyword", "")
    check_keyword_flag = bool(site.get("check_keyword", False)) and bool(keyword)
    notes = []

    row = {
        "DateTime": datetime.now(timezone.utc).isoformat(),
        "Website Name": name,
        "URL": url,
        "Status": "Down",
        "Ping (ms)": "N/A",
        "TCP Connect (ms)": "N/A",
        "TLS Handshake (ms)": "N/A",
        "DNS Time (ms)": "N/A",
        "HTTP TTFB (ms)": "N/A",
        "HTTP FirstChunk (ms)": "N/A",
        "HTTP Total (ms)": "N/A",
        "Redirects": 0,
        "Redirect Times (ms)": "[]",
        "Content Size (KB)": "N/A",
        # REINSTATED: Keyword Check field
        "Keyword Check": "Skipped", 
        "SSL Days Left": "N/A",
        "SSL Expiry Date": "N/A",
        "Probes Summary": {},
        "Notes": ""
    }

    hostname = get_hostname(url or name)
    ip_addr = None

    # DNS local
    try:
        start = time.perf_counter()
        if HAS_DNS:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = min(3, timeout)
            answers = resolver.resolve(hostname, "A", lifetime=min(3, timeout))
            ip_addr = answers[0].to_text() if answers else None
        else:
            addrs = socket.getaddrinfo(hostname, None)
            ip_addr = addrs[0][4][0] if addrs else None
        row["DNS Time (ms)"] = round((time.perf_counter() - start) * 1000, 2)
    except Exception:
        row["DNS Time (ms)"] = "Failed"
        notes.append("DNS failed")

    # TCP connect
    try:
        port = 443 if (url or "").lower().startswith("https") else 80
        start = time.perf_counter()
        with closing(socket.create_connection((hostname, port), timeout=min(timeout, 10))):
            row["TCP Connect (ms)"] = round((time.perf_counter() - start) * 1000, 2)
    except Exception:
        row["TCP Connect (ms)"] = "Failed"
        notes.append("TCP failed")

    # ICMP Ping
    site_use_icmp = site.get("use_icmp", None)
    if site_use_icmp is None:
        site_use_icmp = USE_ICMP_BY_DEFAULT
    if site_use_icmp and HAS_ICMPLIB and ip_addr:
        try:
            ping_res = icmplib.ping(ip_addr, count=1, timeout=2)
            if getattr(ping_res, "is_alive", False):
                row["Ping (ms)"] = round(getattr(ping_res, "avg_rtt", 0.0), 2)
            else:
                row["Ping (ms)"] = "Failed (No Response)"
                notes.append("ICMP failed")
        except Exception:
            row["Ping (ms)"] = "Error"
            notes.append("ICMP error")
    else:
        if not site_use_icmp:
            row["Ping (ms)"] = "Skipped"
        elif not HAS_ICMPLIB:
            row["Ping (ms)"] = "Library Missing"
        else:
            row["Ping (ms)"] = "No IP/Skipped"

    # Measure HTTP phases (primary metric is HTTP TTFB)
    if HAS_REQUESTS and url:
        phases = measure_http_phases(url, timeout=http_timeout, max_first_bytes=65536)
        row["HTTP TTFB (ms)"] = phases.get("ttfb_ms")
        row["HTTP FirstChunk (ms)"] = phases.get("first_chunk_ms")
        row["HTTP Total (ms)"] = phases.get("total_transfer_ms")
        row["Redirects"] = phases.get("redirects", 0)
        row["Redirect Times (ms)"] = json.dumps(phases.get("redirect_times_ms", []))
        row["Content Size (KB)"] = phases.get("content_length") or "Unknown"
        if row.get("DNS Time (ms)") in (None, "Failed"):
            if phases.get("dns_ms") is not None:
                row["DNS Time (ms)"] = phases.get("dns_ms")
        if row.get("TCP Connect (ms)") in (None, "Failed"):
            if phases.get("tcp_ms") is not None:
                row["TCP Connect (ms)"] = phases.get("tcp_ms")
        if row.get("TLS Handshake (ms)") in (None, "Failed"):
            if phases.get("tls_ms") is not None:
                row["TLS Handshake (ms)"] = phases.get("tls_ms")

        sc = phases.get("status_code")
        if sc is None:
            row["Status"] = "Down (HTTP Error)"
            notes.append("HTTP error or timeout")
        else:
            if 200 <= int(sc) < 400:
                ttfb = phases.get("ttfb_ms")
                if isinstance(ttfb, (int, float)) and ttfb > RESPONSE_TIME_THRESHOLD:
                    row["Status"] = "Up (Slow)"
                    notes.append(f"TTFB {ttfb}ms > threshold {RESPONSE_TIME_THRESHOLD}ms")
                else:
                    row["Status"] = "Up"
            else:
                row["Status"] = f"Down (Status {sc})"
                notes.append(f"HTTP status {sc}")
    else:
        if url:
            row["Status"] = "Down (No requests lib)"
            notes.append("requests missing")

    # KEYWORD CHECK: PASSIVE CHECK ONLY (Does NOT affect row["Status"])
    if HAS_REQUESTS and url and check_keyword_flag:
        try:
            # We use a direct GET request here to check content
            r = requests.get(url, timeout=min(5, DEFAULT_HTTP_CHECK_TIMEOUT), allow_redirects=True, verify=VERIFY_SSL)
            
            if keyword.lower() in r.text.lower():
                row["Keyword Check"] = "Pass"
            else:
                row["Keyword Check"] = "Fail"
                notes.append("Keyword missing (record only)") # Ensures no alert trigger
        except Exception:
            row["Keyword Check"] = "Error"
            notes.append("Keyword check error")


    # SSL Expiry
    if (url or "").lower().startswith("https"):
        try:
            # FIX: Moved TLS context/socket creation outside of core loop to optimize non-HTTPS checks
            ctx = ssl.create_default_context()
            with closing(socket.create_connection((hostname, 443), timeout=min(timeout, 10))) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        except Exception:
                            expiry = dateutil_parser.parse(not_after)
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=timezone.utc)
                        else:
                            expiry = expiry.astimezone(timezone.utc)
                        row["SSL Expiry Date"] = expiry.isoformat()
                        row["SSL Days Left"] = (expiry - datetime.now(timezone.utc)).days
        except Exception:
            row["SSL Days Left"] = "Failed"
            notes.append("SSL check failed")

    row["Probes Summary"] = {}
    row["Notes"] = "; ".join(notes).strip()
    return row

# ---------------------------
# confirmation & alerting logic
# ---------------------------
def evaluate_confirmation_strategy(local_failed_bool, external_dns_results, external_http_results, strategy):
    local_failed = bool(local_failed_bool)
    dns_vals = list(external_dns_results.values()) if isinstance(external_dns_results, dict) else []
    http_vals = list(external_http_results.values()) if isinstance(external_http_results, dict) else []
    successes = 0; total = 0
    total += 1
    if not local_failed:
        successes += 1
    for v in dns_vals:
        total += 1
        if v: successes += 1
    for v in http_vals:
        total += 1
        if v: successes += 1
    if total == 0:
        return True
    strategy = (strategy or "majority").lower()
    if strategy == "all":
        return successes == 0
    elif strategy == "majority":
        return successes <= (total // 2)
    elif strategy == "any":
        return successes == 0
    else:
        return successes == 0

def process_result_and_maybe_alert(final_result):
    global site_state
    if final_result is None:
        return None
    name = final_result.get("Website Name", "")
    url = final_result.get("URL", "")
    now_iso = datetime.now(timezone.utc).isoformat()
    status = final_result.get("Status", "")
    local_failure = isinstance(status, str) and status.lower().startswith("down")
    sstate = site_state.get(name, {"consecutive_failures":0,"down_since":None,"alert_sent":False,"last_status":None})
    site_cfg = next((s for s in sites if (s.get("name")==name or s.get("url")==url)), {})
    sensitive = bool(site_cfg.get("sensitive", False))
    strategy = site_cfg.get("confirm_strategy", "all" if sensitive else "majority")
    final_result.setdefault("Probes Summary", {})
    final_result["Probes Summary"]["confirm_strategy"] = strategy
    ps = final_result.get("Probes Summary", {})
    ext_dns = ps.get("external_dns", {}); ext_http = ps.get("external_http", {})
    
    # ALERT LOGIC: ONLY uses the main status (local_failure) and external checks (considered_down).
    # Keyword check is inherently PASSIVE and does NOT factor into local_failure.
    considered_down = evaluate_confirmation_strategy(local_failure, ext_dns, ext_http, strategy)
    
    if considered_down:
        sstate["consecutive_failures"] = int(sstate.get("consecutive_failures", 0) or 0) + 1
        if sstate.get("down_since") is None:
            sstate["down_since"] = now_iso
    else:
        sstate["consecutive_failures"] = 0
        sstate["down_since"] = None
    alert_now = False; alert_reason = None
    if considered_down and not sstate.get("alert_sent", False):
        if sstate.get("consecutive_failures",0) >= ALERT_CONSECUTIVE_FAILURES:
            alert_now = True
            alert_reason = f"Confirmed down by strategy '{strategy}' and {sstate['consecutive_failures']} consecutive failures"
    if considered_down and not alert_now and not sstate.get("alert_sent", False) and sstate.get("down_since"):
        try:
            ds = sstate["down_since"]
            ds_dt = None
            try:
                ds_dt = datetime.fromisoformat(ds).replace(tzinfo=timezone.utc)
            except Exception:
                ds_dt = dateutil_parser.parse(ds).replace(tzinfo=timezone.utc)
            down_minutes = (datetime.now(timezone.utc) - ds_dt).total_seconds() / 60.0
            if down_minutes >= ALERT_MINUTES_DOWN and sstate.get("consecutive_failures",0) >= 1:
                alert_now = True
                alert_reason = f"Down >= {ALERT_MINUTES_DOWN} minutes and confirmed by strategy '{strategy}'"
        except Exception:
            pass
    if alert_now:
        if EMAIL_ENABLED and EMAIL_TO and EMAIL_USER and EMAIL_PASS:
            try:
                send_email_alert(name, final_result, alert_reason)
            except Exception:
                logging.exception("Failed to send alert email")
        logging.info("ALERT SENT for %s: %s", name, alert_reason)
        sstate["alert_sent"] = True
    if (not considered_down) and sstate.get("alert_sent", False):
        if EMAIL_ENABLED and EMAIL_TO and EMAIL_USER and EMAIL_PASS:
            try:
                send_recovery_email(name, final_result)
            except Exception:
                logging.exception("Failed to send recovery email")
        logging.info("RECOVERY for %s", name)
        sstate["alert_sent"] = False
        sstate["consecutive_failures"] = 0
        sstate["down_since"] = None
    sstate["last_status"] = final_result.get("Status")
    site_state[name] = sstate
    save_site_state(site_state)
    final_result["Probes Summary"]["considered_down"] = considered_down
    return final_result

# ---------------------------
# Email helpers (simple, optional)
# ---------------------------
def send_email_alert(site_name, final_result, reason):
    try:
        import smtplib
        from email.mime.text import MIMEText
        subject = f"ALERT: {site_name} - DOWN"
        body = f"Site: {site_name}\nURL: {final_result.get('URL')}\nStatus: {final_result.get('Status')}\nReason: {reason}\nTime (UTC): {datetime.now(timezone.utc).isoformat()}\nProbes Summary: {json.dumps(final_result.get('Probes Summary', {}), indent=2)}\nNotes: {final_result.get('Notes','')}\n"
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = ", ".join(EMAIL_TO)
        smtp_server = EMAIL_SMTP or "smtp.gmail.com"
        if EMAIL_PORT == 465:
            with smtplib.SMTP_SSL(smtp_server, EMAIL_PORT, timeout=10) as s:
                s.login(EMAIL_USER, EMAIL_PASS)
                s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, EMAIL_PORT, timeout=10) as s:
                s.ehlo()
                try:
                    s.starttls()
                    s.ehlo()
                except Exception:
                    pass
                s.login(EMAIL_USER, EMAIL_PASS)
                s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info("Alert email sent for %s", site_name)
    except Exception:
        logging.exception("Failed to send alert email")

def send_recovery_email(site_name, final_result):
    try:
        import smtplib
        from email.mime.text import MIMEText
        subject = f"RECOVERY: {site_name} - UP"
        body = f"Site: {site_name}\nURL: {final_result.get('URL')}\nStatus: {final_result.get('Status')}\nTime (UTC): {datetime.now(timezone.utc).isoformat()}\nProbes Summary: {json.dumps(final_result.get('Probes Summary', {}), indent=2)}\nNotes: {final_result.get('Notes','')}\n"
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = ", ".join(EMAIL_TO)
        smtp_server = EMAIL_SMTP or "smtp.gmail.com"
        if EMAIL_PORT == 465:
            with smtplib.SMTP_SSL(smtp_server, EMAIL_PORT, timeout=10) as s:
                s.login(EMAIL_USER, EMAIL_PASS)
                s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, EMAIL_PORT, timeout=10) as s:
                s.ehlo()
                try:
                    s.starttls()
                    s.ehlo()
                except Exception:
                    pass
                s.login(EMAIL_USER, EMAIL_PASS)
                s.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info("Recovery email sent for %s", site_name)
    except Exception:
        logging.exception("Failed to send recovery email")

# ---------------------------
# Wrapper: retries + external verification
# ---------------------------
def verify_with_retries_and_external(site):
    name = site.get("name") or site.get("Website") or site.get("url")
    url = site.get("url") or site.get("URL") or ""
    hostname = get_hostname(url or name)
    sensitive = bool(site.get("sensitive", False))
    strategy = site.get("confirm_strategy", "all" if sensitive else "majority")

    local = check_site_core(site)
    if local is None:
        return None

    status = local.get("Status", "")
    if not (isinstance(status, str) and status.lower().startswith("down")):
        local["Probes Summary"] = {"local_ok": True}
        return process_result_and_maybe_alert(local)

    # retries
    logging.info("[%s] initial down -> retries=%s delay=%s", name, RETRY_ATTEMPTS, RETRY_DELAY)
    backoff = RETRY_DELAY
    for i in range(RETRY_ATTEMPTS):
        time.sleep(backoff)
        retry = check_site_core(site)
        if retry is None:
            backoff *= 2; continue
        rstatus = retry.get("Status", "")
        if not (isinstance(rstatus, str) and rstatus.lower().startswith("down")):
            retry["Probes Summary"] = {"local_ok_after_retry": True, "retry_index": i+1}
            return process_result_and_maybe_alert(retry)
        local = retry
        backoff *= 2

    # external DNS probes
    ext_dns_results = {}
    for ns in EXTERNAL_DNS_SERVERS:
        try:
            ext_dns_results[ns] = probe_external_dns(hostname, ns, timeout=3)
        except Exception:
            ext_dns_results[ns] = False

    # external HTTP probes
    ext_http_results = {}
    for probe in EXTERNAL_HTTP_PROBES:
        try:
            ext_http_results[probe] = probe_external_http(url, probe, timeout=EXTERNAL_CHECK_TIMEOUT)
        except Exception:
            ext_http_results[probe] = False

    local["Probes Summary"] = {
        "local_status": local.get("Status"),
        "external_dns": ext_dns_results,
        "external_http": ext_http_results,
        "confirm_strategy": strategy
    }

    return process_result_and_maybe_alert(local)

# ---------------------------
# run checks and log rows
# ---------------------------
def run_checks_and_log():
    rows = []
    try:
        for site in sites:
            try:
                if not bool(site.get("enabled", True)):
                    continue
                res = verify_with_retries_and_external(site)
                if res:
                    rows.append(res)
            except Exception:
                logging.exception("Error checking site %s", site.get("name"))
    finally:
        if not rows:
            logging.warning("No results produced during this run.")
        write_log_rows(rows)

# ---------------------------
# CLI diagnostics
# ---------------------------
def diag_url(url):
    print("Diagnostic phase breakdown for:", url)
    phases = measure_http_phases(url, timeout=DEFAULT_HTTP_CHECK_TIMEOUT, max_first_bytes=65536)
    print(json.dumps(phases, indent=2))
    return phases

# ---------------------------
# main loop
# ---------------------------
def monitor_loop():
    # Since the global lock is removed, this function just runs the loop immediately.
    
    if FORCE_RUN_ON_START:
        try:
            logging.info("FORCE_RUN_ON_START enabled — running initial pass.")
            run_checks_and_log()
        except Exception:
            logging.exception("Initial forced run failed.")
            
    # initial run
    try:
        run_checks_and_log()
    except Exception:
        logging.exception("Initial run failed.")

    logging.info("Entering interval monitor loop (interval %s seconds)", MONITOR_INTERVAL)
    while True:
        start = time.time()
        try:
            run_checks_and_log()
        except Exception:
            logging.exception("Error during scheduled run")
        elapsed = time.time() - start
        time.sleep(max(1, MONITOR_INTERVAL - elapsed))

if __name__ == "__main__":
    if "--run-now" in sys.argv:
        run_checks_and_log()
        sys.exit(0)
    if "--diag" in sys.argv:
        idx = sys.argv.index("--diag")
        if idx + 1 < len(sys.argv):
            target = sys.argv[idx + 1]
            diag_url(target)
            sys.exit(0)
        else:
            print("Usage: monitor_backend.py --diag https://example.org")
            sys.exit(1)
    monitor_loop()