import os
import sys
import logging
import subprocess
import yaml
import numpy as np
import pandas as pd
import streamlit as st
from datetime import datetime
from filelock import FileLock, Timeout 
from dotenv import dotenv_values
from streamlit_echarts import st_echarts
from streamlit_autorefresh import st_autorefresh
from dateutil import parser as dateutil_parser
from dateutil import tz as dateutil_tz
import math
import json
import base64

# Optional: For the chatbot animation
try:
    from streamlit_lottie import streamlit_lottie
    import requests
except ImportError:
    streamlit_lottie = None
    requests = None
    print("WARNING: streamlit-lottie or requests library not found. Chatbot animation will be skipped.")

# --- Robot Constants ---
ROBOT_NAME = "ORSA-AI"
LOTTIE_URL = "https://lottie.host/17e29621-e0c3-4d6d-88b9-e13768ef6134/x1OQWJ05z9.json" 
robot_lottie = None
if streamlit_lottie and requests:
    try:
        @st.cache_data(ttl=3600)
        def fetch_lottie(url):
            return requests.get(url).json()
        robot_lottie = fetch_lottie(LOTTIE_URL)
    except Exception:
        pass


# ==================================================================================================
# CORE CONFIGURATION & SETUP
# ==================================================================================================
try:
    env_vars = dotenv_values()
    for key, value in env_vars.items():
        if key is not None and value is not None:
            os.environ[key] = value
except Exception as e:
    logging.warning("Failed to load environment variables from .env: %s", e)

CONFIG_FILE = os.getenv("SITES_YAML", "sites.yaml")
LOG_FILE = os.getenv("LOG_FILE", "website_monitor_log.csv")
LOCK_FILE = LOG_FILE + ".lock"
SITE_STATE_FILE = os.getenv("SITE_STATE_FILE", "site_state.json")
SITE_STATE_LOCK = SITE_STATE_FILE + ".lock"
PROCESS_LOCK_FILE = os.getenv("PROCESS_LOCK_FILE", "monitor_run.lock") 

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format="%(asctime)s - %(levelname)s - %(message)s")

IST_TZ = "Asia/Kolkata"
IST_LABEL = "IST"
LOG_PAGE_SIZE = 10 

# Runtime overrides
try:
    MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL", 1800))
except Exception:
    MONITOR_INTERVAL = 1800
try:
    SSL_ALERT_DAYS = int(os.getenv("SSL_ALERT_DAYS", 30))
except Exception:
    SSL_ALERT_DAYS = 30
try:
    RESPONSE_TIME_THRESHOLD = float(os.getenv("RESPONSE_TIME_THRESHOLD", 3000)) 
except Exception:
    RESPONSE_TIME_THRESHOLD = 3000.0
try:
    DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", 10))
except Exception:
    DEFAULT_TIMEOUT = 10

USE_ICMP_BY_DEFAULT = os.getenv("USE_ICMP_BY_DEFAULT", "true").lower() in ("1", "true", "yes")
START_BACKEND = os.getenv("START_BACKEND", "true").lower() in ("1", "true", "yes")

# ------------------------------
# Helper: sanitize options to JSON-serializable types (Needed for ECharts)
# ------------------------------
def _to_native(x):
    """Convert numpy / pandas scalar to native python types."""
    if x is None:
        return None
    try:
        if pd.isna(x):
            return None
    except Exception:
        pass
    if isinstance(x, (np.integer, np.int64, np.int32)):
        return int(x)
    if isinstance(x, (np.floating, np.float64, np.float32)):
        return float(x)
    if isinstance(x, (np.bool_, bool)):
        return bool(x)
    if isinstance(x, (pd.Timestamp, datetime)):
        try:
            return str(x)
        except Exception:
            return x.isoformat() if hasattr(x, "isoformat") else str(x)
    if isinstance(x, np.ndarray):
        return [_to_native(y) for y in x.tolist()]
    if isinstance(x, pd.Series):
        return [_to_native(y) for y in y.tolist()]
    if isinstance(x, (int, float, str, bool)):
        return x
    try:
        return int(x)
    except Exception:
        try:
            return float(x)
        except Exception:
            return str(x)

def sanitize_for_json(obj):
    """Recursively convert an object (dict/list) to JSON-serializable Python builtins."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[str(k)] = sanitize_for_json(v)
        return out
    elif isinstance(obj, list):
        return [sanitize_for_json(v) for v in obj]
    elif isinstance(obj, tuple):
        return [sanitize_for_json(v) for v in obj]
    else:
        return _to_native(obj)

# ------------------------------
# Backend Control Functions 
# ------------------------------
def run_monitor_in_background(instant_check=False):
    """Starts the backend script with optional instant check flag."""
    if 'monitor_process' in st.session_state and st.session_state.monitor_process is not None:
        try:
            if st.session_state.monitor_process.poll() is None:
                logging.info("Backend process already running.")
                if instant_check:
                    try:
                        st.session_state.monitor_process.terminate()
                        del st.session_state.monitor_process
                        logging.info("Terminated existing background process for instant run.")
                    except Exception as term_e:
                        logging.warning("Could not terminate existing process: %s", term_e)
                    st.rerun()
                return
        except Exception:
            try:
                del st.session_state.monitor_process
            except Exception:
                pass

    try:
        cmd = [sys.executable, "monitor_backend.py"]
        if instant_check:
            cmd.append("--run-now")
            logging.info("Starting instant check...")
            p = subprocess.Popen(cmd)
            p.wait()
            st.cache_data.clear() 
            st.rerun()
        else:
            logging.info("Starting continuous backend monitor...")
            # Use FileLock/Timeout check logic to prevent process chaos on Streamlit restart
            try:
                with FileLock(PROCESS_LOCK_FILE, timeout=0): 
                    p = subprocess.Popen(cmd)
                    st.session_state.monitor_process = p
                    logging.info("Started monitor_backend.py with PID %s", p.pid)
            except Timeout:
                logging.warning("Skipping background start: Backend process lock detected. Monitor already running.")
            except Exception as e:
                logging.error(f"Failed during monitored process launch check: {e}")


    except Exception as e:
        st.error(f"Failed to start monitoring backend: {e}")
        logging.error("Failed to start backend: {e}")

if START_BACKEND and 'monitor_process' not in st.session_state:
    try:
        run_monitor_in_background()
    except Exception:
        logging.debug("Auto-start backend failed or disabled externally.")

# ------------------------------
# Data Loading and Utility Functions
# ------------------------------
def parse_dt_flexible_scalar(x):
    """Parses a flexible date string to a timezone-aware Pandas Timestamp."""
    try:
        if pd.isna(x):
            return pd.NaT
        t = pd.to_datetime(x, utc=True, errors="coerce")
        if not pd.isna(t):
            return t
    except Exception:
        pass
    try:
        dt = dateutil_parser.parse(str(x), fuzzy=True)
        ts = pd.Timestamp(dt)
        ts = ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")
        return ts
    except Exception:
        return pd.NaT

# FIX: Corrected function to handle FutureWarning by explicit casting
def parse_dt_flexible_series(series):
    """Applies flexible date parsing across a Pandas Series."""
    try:
        parsed = pd.to_datetime(series, utc=True, errors="coerce")
    except Exception:
        # Fallback creation: start with NaN and try to fill (ensure dtype is UTC)
        parsed = pd.Series([pd.NaT] * len(series), index=series.index, dtype='datetime64[ns, UTC]')
        
    mask = parsed.isna()
    if mask.any():
        parsed_fallback = series[mask].apply(parse_dt_flexible_scalar)
        
        # Explicitly convert fallback series to UTC datetime to avoid FutureWarning
        parsed_fallback = pd.to_datetime(parsed_fallback, utc=True, errors='coerce')

        parsed.loc[mask] = parsed_fallback
    return parsed

def to_ist_string(ts):
    """Converts UTC timestamp to IST string format."""
    try:
        t = parse_dt_flexible_scalar(ts)
        if pd.isna(t):
            return "N/A"
        t_ist = t.tz_convert(IST_TZ)
        return t_ist.strftime("%Y-%m-%d %H:%M:%S ") + IST_LABEL
    except Exception:
        return str(ts)

# New: Function to convert DataFrame to CSV for download
def convert_df_to_csv(df):
    """Converts a DataFrame to CSV format."""
    df_copy = df.copy()
    
    if "DateTime" in df_copy.columns:
        df_copy["DateTime"] = df_copy["DateTime"].apply(lambda x: to_ist_string(x) if pd.notna(x) else x)

    return df_copy.to_csv(index=False).encode('utf-8')

@st.cache_data(ttl=20)
def load_data():
    """
    Loads and preprocesses data from the log CSV file.
    """
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        return pd.DataFrame()
    try:
        with FileLock(LOCK_FILE, timeout=5):
            df = pd.read_csv(LOG_FILE, keep_default_na=True)
    except Exception:
        try:
            df = pd.read_csv(LOG_FILE, keep_default_na=True)
        except Exception:
            return pd.DataFrame()

    df.columns = df.columns.str.strip()
    if "DateTime" in df.columns: df["DateTime"] = parse_dt_flexible_series(df["DateTime"])
    for c in df.select_dtypes(include=["object"]).columns: df[c] = df[c].astype(str).str.strip().replace({"nan": ""})
    
    # --- Clean up Old/Deprecated Columns ---
    df = df.drop(columns=["HTTP Time (ms)", "Domain Days Left", "Domain Expiry Date"], errors='ignore')

    # List of all numeric columns, including the new phase timings
    numeric_cols = [
        "Ping (ms)", "TCP Connect (ms)", "TLS Handshake (ms)",
        "DNS Time (ms)", "HTTP TTFB (ms)", "HTTP FirstChunk (ms)", 
        "HTTP Total (ms)", "Content Size (KB)", "SSL Days Left", 
        "Redirects"
    ]

    for col in numeric_cols:
        if col in df.columns:
            # Map failure strings to None before converting to numeric
            df[col] = df[col].replace([
                "N/A", "Failed", "Error", "WHOIS Failed", "Restricted", 
                "Failed (No Response)", "Library Missing", "No IP/Skipped", ""
            ], None)
            df[col] = pd.to_numeric(df[col], errors="coerce")
    
    if "Status" not in df.columns: df["Status"] = "Unknown"
    if "Website Name" not in df.columns:
        if "Website" in df.columns: df = df.rename(columns={"Website": "Website Name"})
        elif "URL" in df.columns: df["Website Name"] = df["URL"].astype(str)
        else: df["Website Name"] = df.index.astype(str)
        
    if "SSL Expiry Date" in df.columns: df["SSL Expiry Date Parsed"] = parse_dt_flexible_series(df["SSL Expiry Date"])
    else: df["SSL Expiry Date Parsed"] = pd.NaT

    return df

def load_sites_yaml(path=CONFIG_FILE):
    """Loads site configuration from the YAML file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
            return cfg.get("sites", []) or []
    except Exception:
        return []

def load_site_state(path=SITE_STATE_FILE):
    """Loads persistent site state for alerting logic."""
    if not os.path.exists(path):
        return {}
    
    # 1. Try reading with file lock
    try:
        with FileLock(SITE_STATE_LOCK, timeout=5):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    # 2. If lock fails, try reading without lock (graceful degradation)
    except Exception:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        # 3. If everything fails, log and return empty dict
        except Exception:
            logging.debug("Cannot read site state file; returning empty.")
            return {}

def status_color(status):
    """Returns a color hex code based on site status (Green/Red/Orange)."""
    try:
        if isinstance(status, str):
            s = status.strip().lower()
            if s.startswith("up") or s in ("up", "ok", "online"):
                return "#198754"  # Green
            if "slow" in s or "warning" in s:
                return "#ffc107"  # Amber
            if s.startswith("down") or s in ("down", "offline", "error", "fail", "failed"):
                return "#dc3545"  # Red
            if "ping error" in s: # Added a case for Ping Error
                return "#fd7e14" # Orange 
    except Exception:
        pass
    return "#6c757d"  # Gray

def safe_float_or_none(x):
    """Converts numeric values to float, returns None if non-numeric/failure string."""
    try:
        val = pd.to_numeric(x, errors='coerce')
        return float(val) if pd.notna(val) else None
    except Exception:
        return None

def format_numeric_columns(df_obj, cols):
    """
    Formats numeric columns in a DataFrame, leaving failure strings as-is.
    Ensures Ping values are correctly handled as floats or error strings.
    """
    for col in cols:
        if col in df_obj.columns:
            def _fmt(x):
                # Try to handle strings first to retain error messaging
                sx = str(x).strip()
                if sx in ["Failed (No Response)", "Library Missing", "No IP/Skipped", "Error", "Failed"]:
                    return "Ping Error" if col == "Ping (ms)" else "Error"
                
                # If it's not a known error string, try to format as a number
                try:
                    val = float(x)
                    if pd.notna(val):
                        return f"{val:.2f}"
                except (ValueError, TypeError):
                    pass
                
                return sx
            
            df_obj[col] = df_obj[col].apply(_fmt)
    return df_obj

# --- Chatbot Logic Core ---
@st.cache_data
def load_robot_lottie():
    """Loads the Lottie JSON file for the animation."""
    if not streamlit_lottie:
        return None
    try:
        return requests.get(LOTTIE_URL).json()
    except Exception:
        return None
    
def analyze_downtime(site_name, df_latest, threshold_ms, alert_days):
    """Analyzes a specific site's status and generates a robot response."""
    # Ensure site_name exists in the index before proceeding
    if site_name not in df_latest['Website Name'].values:
        return f"BEEP BOOP! Data for **{site_name}** not found in the latest snapshot."
        
    site_data = df_latest[df_latest['Website Name'] == site_name].iloc[0]
    
    status = site_data.get('Status', 'Unknown').strip()
    ttfb = safe_float_or_none(site_data.get('HTTP TTFB (ms)'))
    tls = safe_float_or_none(site_data.get('TLS Handshake (ms)'))
    ssl_days = safe_float_or_none(site_data.get('SSL Days Left'))
    notes = site_data.get('Notes')
    keyword_status = site_data.get('Keyword Check', 'N/A')
    
    response = [f"BEEP BOOP! Analyzing **{site_name}**..."]

    if status.lower().startswith("up"):
        if 'slow' in status.lower():
            response.append(f"STATUS: **UP (SLOW)** 🟡")
            response.append(f"DIAGNOSIS: TTFB ({ttfb:.2f} ms) is above the critical threshold of {threshold_ms} ms. This means the **server is generating the page slowly**. ACTION: Check database queries and caching layers!")
        else:
            response.append(f"STATUS: **UP (FAST)** 🟢")
            response.append(f"DIAGNOSIS: **Nominal Performance.** TTFB is {ttfb:.2f} ms.")
            
    elif status.lower().startswith("down"):
        response.append(f"STATUS: **DOWN** 🔴 ({status})")
        
        if '403' in status:
            response.append("DIAGNOSIS: This is a **Forbidden Access** error. The server is accessible, but it's blocking your request. ACTION: Check the **GeoServer's IP whitelist or authentication rules** for the monitor's IP.")
        elif '404' in status:
            response.append("DIAGNOSIS: **Resource Not Found**. ACTION: Verify the URL in `sites.yaml` is correct and that the endpoint exists on the server.")
        elif 'error' in status or ttfb is None:
            response.append("DIAGNOSIS: The request timed out or returned a general error. ACTION: Investigate **network path failure** or check if the **web server application is frozen**.")
        else:
            response.append(f"DIAGNOSIS: The site returned HTTP Status **{status.split()[-1]}**. The server replied, but with an error code. Check server application logs.")

    else:
        response.append(f"STATUS: **{status}**")
        response.append("DIAGNOSIS: Status is ambiguous. Investigate immediately. BEEP!")

    response.append("---")
    
    # Keyword Check added back as informational
    if keyword_status != 'N/A' and keyword_status != 'Skipped':
        if keyword_status == 'Fail':
             response.append("❗ **CONTENT FAILURE WARNING (PASSIVE):** The expected keyword was **NOT found**. This may mean the page is displaying an error or placeholder content. The site is marked UP only because the HTTP status was OK, but the content is likely broken.")
        else:
             response.append(f"CONTENT CHECK: Keyword check returned **{keyword_status}**.")
    
    # Detailed performance check
    if ttfb is not None and ttfb > 1000:
        response.append(f"**PERFORMANCE NOTE:** TTFB is over 1 second. Optimization should target **server-side caching and database efficiency**.")
    if tls is not None and tls > 200:
        response.append(f"**PERFORMANCE NOTE:** TLS Handshake took {tls:.2f} ms. This is slow for a negotiation. Check server cipher configuration or latency.")

    # SSL check
    if ssl_days is not None and ssl_days < alert_days:
        response.append(f"**⚠️ URGENT SSL ALERT:** Certificate expires in just **{int(ssl_days)} days**! Renew immediately.")
    
    if notes:
        response.append(f"**NOTES:** {notes}")
    
    return "\n\n".join(response)

# --- Chart Utility Function ---
def create_line_chart_options(metric_name, data_points, color, site_names, y_name="Time (ms)", threshold=None):
    """Generates stable ECharts options for a single metric line graph with high contrast styling."""
    formatter = "{{b}} <br/> {}: {{c}} {}".format(metric_name, y_name.split(' ')[0])
    
    # Get the data text color defined in the sidebar/session state
    data_text_color = st.session_state.get("data_text_color_css", "#222222") # Default to dark text

    markline_data = []
    if threshold is not None:
        markline_data.append({"yAxis": threshold, "name": "Alert Threshold"})

    return {
        "tooltip": {
            "trigger": "axis", 
            "formatter": formatter,
            "backgroundColor": "#FFFFFF", # Light background for tooltips
            "borderColor": color,
            "borderWidth": 1,
            "textStyle": {"color": "#222222"}
        },
        "xAxis": {"type": "category", "data": site_names, "axisLabel": {"rotate": 35, "interval": 0, "margin": 10, "color": data_text_color, "fontSize": 10}}, # Updated color and rotation
        "yAxis": {"type": "value", "name": y_name, "nameTextStyle": {"color": data_text_color}, "axisLabel": {"color": data_text_color}}, # Updated color
        "series": [ {
            "name": metric_name, 
            "type": "line", 
            "data": data_points, 
            "smooth": True,
            "lineStyle": {"color": color, "width": 3},
            "symbol": "circle",
            "symbolSize": 8,
            "showSymbol": True,
            "areaStyle": {"opacity": 0.1, "color": color}, # Subtly tinted area
            "markLine": {
                "silent": True,
                "lineStyle": {"type": "dashed", "color": "#FF8C42"},
                "data": markline_data
            }
        } ],
        "grid": {"bottom": "30%", "top": "15%", "containLabel": True, "left": "5%", "right": "5%"}, # Adjusted grid for better fit
        "dataZoom": [{"type": 'slider', "xAxisIndex": 0, "filterMode": 'none', "backgroundColor": "#DDD", "dataBackground": {"areaStyle": {"color": "#AAA"}}, "fillerColor": "rgba(0, 123, 255, 0.4)"}],
        "backgroundColor": "transparent"
    }

# --- HTML Table Renderer (Function Definition restored) ---
def render_table_with_badges(df_table, title=""):
    if df_table.empty:
        st.info("No data to show.")
        return

    # Build HTML table header
    header_html = "<thead><tr>"
    # Mapping for column display names in tables (for brevity)
    column_display_map = {
        "Website Name": "Site", "Status": "Status", "Sensitive": "Sens.", 
        "Confirmed Down": "Down", "Suspect": "Suspect", "Ping (ms)": "Ping (ms)", 
        "HTTP TTFB (ms)": "TTFB (ms)", "TLS Handshake (ms)": "TLS (ms)",
        "SSL Days Left": "SSL Days", "Keyword Check": "Keyword" # Added Keyword Check back
    }
    
    for c in df_table.columns:
        display_name = column_display_map.get(c, c)
        # Align badges/status centered, align text left
        align = "center" if c in ["Sensitive", "Confirmed Down", "Suspect", "Status", "SSL Days Left", "Keyword Check"] else "left"
        header_html += f"<th style='text-align:{align}; padding: 10px 12px;'>{display_name}</th>"
    header_html += "</tr></thead>"

    rows_html = []
    for _, r in df_table.iterrows():
        row_html = "<tr>"
        for c in df_table.columns:
            val = r[c]
            cell_content = ""
            
            # special handling for certain columns
            if c == "Sensitive":
                cell_content = "<span class='badge badge-sens'>SENSITIVE</span>" if bool(val) else ""
            elif c == "Confirmed Down":
                cell_content = "<span class='badge badge-confirm'>DOWN</span>" if bool(val) else ""
            elif c == "Suspect":
                cell_content = "<span class='badge badge-suspect'>SUSPECT</span>" if bool(val) else ""
            elif c == "Status":
                s = str(val).strip()
                arrow = ""
                # Use standard colors defined by the CSS variables
                if s.lower().startswith("up") and "slow" not in s.lower():
                    arrow = " <span style='color: var(--status-up);'>●</span>"
                elif "slow" in s.lower():
                    arrow = " <span style='color: var(--status-warn);'>●</span>"
                elif s.lower().startswith("down") or "error" in s.lower() or "fail" in s.lower():
                    arrow = " <span style='color: var(--status-down);'>●</span>"
                cell_content = f"<b>{s}</b>{arrow}"
            elif c == "Keyword Check":
                s = str(val).strip().lower()
                if s == 'pass':
                    cell_content = "✅ Pass"
                elif s == 'fail':
                    cell_content = "❌ Fail"
                elif s == 'error':
                    cell_content = "⚠️ Error"
                else:
                    cell_content = s
            elif c == "DateTime":
                try:
                    cell_content = to_ist_string(val)
                except Exception:
                    cell_content = str(val)
            else:
                # Use the raw formatted value from format_numeric_columns (which handles Ping ms/Error)
                cell_content = str(val) 
            
            # Align badges/status centered, align text left
            align = "center" if c in ["Sensitive", "Confirmed Down", "Suspect", "Status", "SSL Days Left", "Keyword Check"] else "left"
            row_html += f"<td style='text-align:{align};' class='table-cell'>{cell_content}</td>"
        row_html += "</tr>"
        rows_html.append(row_html)

    table_html = f"<table class='stDataFrame'><tbody>{header_html}{''.join(rows_html)}</tbody></table>"
    if title:
        st.markdown(f"### {title}")
    st.markdown(table_html, unsafe_allow_html=True)


# ==========================================================
# UI: LAYOUT AND RENDERING
# ==========================================================
st.set_page_config(page_title="ORSAC Monitor", layout="wide", initial_sidebar_state="auto")

# --- Session State Initialization (CRITICAL FIX: Initialization moved here) ---
if 'event_log_page' not in st.session_state:
    st.session_state.event_log_page = 0
if 'data_text_color_css' not in st.session_state:
    st.session_state.data_text_color_css = "#222222" # Default dark text for white background
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = [] 

# Initializing default keys for sidebar controls (FIXED: Moved to top level)
if 's_accent' not in st.session_state: st.session_state.s_accent = "Blue" # Set default accent to Blue
if 's_data_color' not in st.session_state: st.session_state.s_data_color = "Black"
if 's_compact' not in st.session_state: st.session_state.s_compact = False
if 's_watch' not in st.session_state: st.session_state.s_watch = False
if 's_watch_interval' not in st.session_state: st.session_state.s_watch_interval = "10 seconds"
if 's_headline_color' not in st.session_state: st.session_state.s_headline_color = "Black"
if 's_headline_bg' not in st.session_state: st.session_state.s_headline_bg = "None"


# Sidebar controls
with st.sidebar:
    # --- Logo and Aesthetics Controls (Restored to sidebar) ---
    st.image("logo.png", width='stretch')
    
    # PLACEHOLDER HACK for consistent logo background
    st.markdown(
        """
        <style>
        /* Target logo container and force light background */
        section[data-testid="stSidebar"] img {
            background-color: #F7F8FA !important;
            border-radius: 4px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    
    st.markdown("---")
    
    # === DEVELOPER SIGNATURE (Styled with 3D effect) ===
    st.markdown(
        """
        <div style="text-align: center; font-size: 14px; color: var(--text-primary); padding: 10px 0; 
                    border-radius: 8px;">
            <strong style="color: #444;">Developed by:</strong><br>
            <span class="dev-signature" style="font-family: monospace; font-size: 16px; font-weight: 800;">
                ChinmayachittaranjanBrik
            </span><br>
            <em style="color: #666; font-size: 12px;">(Jr. Cloud Architect)</em>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("## Appearance")
    
    # Use keys for select boxes to store state
    accent = st.selectbox("Accent Color", options=["Blue", "Cyan", "Magenta", "Lime", "Yellow"], index=0, key='s_accent')
    
    DATA_COLOR_MAP = {
        "Black": "#222222", "Gray": "#444444", "Blue": "#007BFF"
    }
    
    data_color_choice = st.selectbox("Data Text Color", options=list(DATA_COLOR_MAP.keys()), index=0, key='s_data_color')
    data_text_color = DATA_COLOR_MAP.get(data_color_choice, "#222222")
    st.session_state.data_text_color_css = data_text_color
    
    compact = st.checkbox("Compact mode (denser layout)", value=False, key='s_compact')
    
    st.markdown("---")
    st.markdown("### Headline styling")
    headline_color_choice = st.selectbox("Headline color", options=["Black", "Blue", "Gray"], index=0, key='s_headline_color')
    headline_bg_choice = st.selectbox("Headline background (pill)", options=["None", "Subtle White", "Subtle Blue"], index=0, key='s_headline_bg')
    st.caption("Headlines will be bold and solid color. Background pill helps them stand out.")
    st.markdown("---")


# Accent map / headline styling (Read from session state)
ACENT_MAP = {
    "Blue": {"neon": "#007BFF", "muted": "#0056b3"},
    "Cyan": {"neon": "#17A2B8", "muted": "#008899"},
    "Magenta": {"neon": "#DC3545", "muted": "#BB2C37"},
    "Lime": {"neon": "#28A745", "muted": "#198754"},
    "Yellow": {"neon": "#FFC107", "muted": "#D39E00"}
}
accent_neon = ACENT_MAP.get(st.session_state.s_accent, ACENT_MAP["Blue"])["neon"]
accent_muted = ACENT_MAP.get(st.session_state.s_accent, ACENT_MAP["Blue"])["muted"]

HEADLINE_COLOR_MAP = {
    "Black": "#222222", "Blue": "#007BFF", "Gray": "#444444"
}
headline_color = HEADLINE_COLOR_MAP.get(st.session_state.s_headline_color, "#222222")

headline_bg_choice = st.session_state.s_headline_bg
if headline_bg_choice == "None":
    headline_bg = "transparent"
    headline_bg_padding = "0"
    headline_bg_radius = "0"
elif headline_bg_choice == "Subtle White":
    headline_bg = "rgba(255,255,255,0.8)"
    headline_bg_padding = "6px 10px"
    headline_bg_radius = "6px"
else:  # Subtle Blue
    headline_bg = "rgba(0, 123, 255, 0.1)"
    headline_bg_padding = "6px 10px"
    headline_bg_radius = "6px"

# ------------------------------
# 0. CUSTOM CSS (VISUAL SHELL) - FINAL VERSION
# ------------------------------
css = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

:root {{
    /* Professional White Theme Colors */
    --bg: #FFFFFF; 
    --panel: #F7F8FA; /* Card/Content background */
    --text-primary: #222222;
    --text-secondary: #6c757d;
    
    /* Status Colors (Bootstrap style) */
    --status-up: #198754; 
    --status-warn: #ffc107; 
    --status-down: #dc3545; 
    --sidebar-bg: #E9ECEF; /* Very light gray/blue for sidebar contrast */

    /* Accent Colors */
    --accent: {accent_neon};
    --accent-muted: {accent_muted};
    --headline-color: {headline_color};
    --headline-bg: {headline_bg};
    --headline-bg-padding: {headline_bg_padding};
    --headline-bg-radius: {headline_bg_radius};
    --data-text-color: {data_text_color}; /* Controlled by user select */
    --signature-color: #222222; /* Signature Text Color */
}}

body {{
    background: var(--bg);
    color: var(--text-primary) !important; 
    font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}}

.stApp .block-container {{
    background: var(--bg); 
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.05); /* Subtle shadow on main content */
    border: 1px solid #E0E0E0; /* Light border for definition */
}}

/* Sidebar Styling Overrides */
section[data-testid="stSidebar"] {{
    background-color: var(--sidebar-bg) !important;
    color: var(--text-primary) !important; 
}}
/* Ensure all text in the sidebar is dark and readable */
section[data-testid="stSidebar"] .stMarkdown h3,
section[data-testid="stSidebar"] .stMarkdown h2,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] p {{
    color: var(--text-primary) !important;
}}

/* Header Background (Main Window Toolbar) */
.st-emotion-cache-1r6j0o9 {{ 
    background-color: var(--bg); 
}}
.st-emotion-cache-1r6j0o9 img {{ 
    background-color: rgba(255, 255, 255, 0.9);
    border-radius: 4px;
}}

/* Signature 3D Text Shadow - Target the custom class applied to the span */
.dev-signature span {{
    color: var(--signature-color) !important;
    text-shadow: 
        1.5px 1.5px 0px rgba(0,0,0,0.2), /* Dark shadow below */
        -1px -1px 0px rgba(255,255,255,0.8); /* Light highlight above */
}}


/* Main title and subheaders */
.futuristic-title {{
    font-size: 32px; 
    font-weight: 800;
    letter-spacing: 0.8px;
    color: var(--headline-color);
    display:inline-block;
    line-height:1;
    text-transform:uppercase;
    padding: var(--headline-bg-padding);
    border-radius: var(--headline-bg-radius);
    background: var(--headline-bg);
    margin-bottom: 15px;
}}
.futuristic-sub, h2, h3, h4, .stMarkdown h2, .stMarkdown h3 {{
    color: var(--headline-color) !important;
    font-weight: 700;
    padding: var(--headline-bg-padding);
    border-radius: var(--headline-bg-radius);
    background: var(--headline-bg);
}}

/* KPI Card Styling - High Contrast */
.kpi-card {{
    background: var(--panel); 
    padding: 15px;
    border-radius: 6px;
    text-align: center;
    border: 1px solid #DDD;
    box-shadow: 0 2px 5px rgba(0,0,0,0.05); /* Clean, professional shadow */
    transition: all 0.3s ease-in-out;
}}

.kpi-card-up {{ border-left: 5px solid var(--status-up); }}
.kpi-card-slow {{ border-left: 5px solid var(--status-warn); }}
.kpi-card-down {{ border-left: 5px solid var(--status-down); }}
.kpi-card-total {{ border-left: 5px solid var(--accent); }}

.kpi-value {{
    font-size: 30px; 
    font-weight: 800;
    color: var(--text-primary) !important; /* Always dark text */
}}
.kpi-label {{
    color: var(--text-secondary) !important;
}}

/* Table Styling */
.stDataFrame {{
    border-radius: 8px;
    overflow: hidden;
    background: var(--panel); 
    border: 1px solid #CCC; 
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05); 
    font-size: 13px;
}}

table.dataframe thead th {{
    background: #E9ECEF !important; /* Light header background */
    color: var(--text-primary) !important; 
    border-bottom: 2px solid var(--accent) !important; 
}}
table.dataframe tbody td {{
    color: var(--text-primary) !important; 
    border-bottom: 1px solid #EEE !important; 
}}

/* Chatbot Container */
div[data-testid="stVerticalBlock"] > div[data-testid="stHorizontalBlock"] > div[data-testid="stVerticalBlock"] > div[data-testid="stVerticalBlock"] {{
    background-color: var(--panel); /* Light card background for the chat/bot area */
    border-radius: 8px;
    padding: 10px;
    border: 1px solid #DDD;
    margin-bottom: 20px;
}}
</style>
"""

st.markdown(css, unsafe_allow_html=True)

# Autorefresh: low-pressure UI refresh (60s) and optional watch refresh
st_autorefresh(interval=60 * 1000, key="refresh_ui_hidden")

# --- Load Data (Needs to be here for sidebar bot and main content) ---
df = load_data()
sites_yaml = load_sites_yaml()
sites_map = {s.get("name"): s for s in sites_yaml if s.get("name")}
site_state = load_site_state()

if df.empty:
    st.info("Monitoring process has started — waiting for first metrics. Check logs if it takes longer than one run.")
    st.stop()

# Prepare latest data snapshot (used by KPIs and Chatbot)
if "DateTime" in df.columns and df["DateTime"].notna().any():
    df_latest = df.sort_values("DateTime", ascending=False).drop_duplicates(subset=["Website Name"], keep="first").reset_index(drop=True)
else:
    df_latest = df.drop_duplicates(subset=["Website Name"], keep="last").reset_index(drop=True)

now_utc = pd.Timestamp.now(tz="UTC")
df_latest["_Status_norm"] = df_latest["Status"].astype(str).str.strip().str.lower()

# Calculate dynamic metrics
total_sites = len(df_latest)
up_count = int(df_latest["_Status_norm"].str.contains("^up$", na=False).sum()) # Only 'up' (not slow)
slow_count = int(df_latest["_Status_norm"].str.contains("slow", na=False).sum())
down_count = int(df_latest["_Status_norm"].str.contains("down|error|fail", na=False).sum())

monitor_interval_str = f"{MONITOR_INTERVAL//60} min"

# Calculate display time
if "DateTime" in df.columns and df["DateTime"].notna().any():
    last_monitored = df["DateTime"].max()
    last_monitored_str = to_ist_string(last_monitored)
else:
    last_monitored_str = "N/A"

# Compute Expiry Days (Ensure calculations are done on the numeric version of the data)
if "SSL Expiry Date Parsed" in df_latest.columns:
    mask_ssl = df_latest["SSL Expiry Date Parsed"].notna()
    if mask_ssl.any():
        # Explicitly cast the Series to datetime64[ns, UTC] for correct subtraction
        ssl_dates_series = df_latest.loc[mask_ssl, "SSL Expiry Date Parsed"].copy().astype('datetime64[ns, UTC]')
        time_left = ssl_dates_series.sub(now_utc)
        df_latest.loc[mask_ssl, "SSL Days Left"] = time_left.dt.days


# Enrich latest snapshot with sensitive/site_state flags
def _get_state(name, key, default=None):
    try:
        return site_state.get(name, {}).get(key, default)
    except Exception:
        return default

df_latest["Sensitive"] = df_latest["Website Name"].apply(lambda n: bool((sites_map.get(n) or {}).get("sensitive", False)))
df_latest["Alert Sent"] = df_latest["Website Name"].apply(lambda n: bool(_get_state(n, "alert_sent", False)))
df_latest["Consecutive Failures"] = df_latest["Website Name"].apply(lambda n: int(_get_state(n, "consecutive_failures", 0) or 0))
df_latest["Down Since"] = df_latest["Website Name"].apply(lambda n: _get_state(n, "down_since", None))
df_latest["Confirmed Down"] = df_latest["Alert Sent"]
df_latest["Suspect"] = df_latest["Consecutive Failures"].apply(lambda x: x > 0 and x < 3)

# Get site names for chart x-axis
site_names = df_latest["Website Name"].astype(str).tolist()

# ==================================================================================================
# HEADER ROW & ACTION BAR
# ==================================================================================================
header_col, button_col = st.columns([0.65, 0.35])

with header_col:
    # Title and Subtitle with Custom Styling
    st.markdown(f"<div class='futuristic-title'>ORSAC Website Monitoring Dashboard 🚀</div>", unsafe_allow_html=True)
    st.markdown(f"<div class='futuristic-sub'>Last Check: {last_monitored_str} | Interval: {monitor_interval_str}</div>", unsafe_allow_html=True)

with button_col:
    st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True) # Spacer for vertical alignment
    if st.button("RUN INSTANT CHECK", key="instant_check_button", help="Triggers a one-time monitoring run now.", type="secondary", use_container_width=True):
        # Clears data cache before re-running to ensure the new log file is read.
        st.cache_data.clear()
        run_monitor_in_background(instant_check=True)

st.markdown("---")

# ==========================================================
# 1. KEY PERFORMANCE INDICATORS (KPI)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>SYSTEM HEALTH OVERVIEW</h2>", unsafe_allow_html=True)

kpi_cols = st.columns(4)

# KPI 1: Total Sites
with kpi_cols[0]:
    st.markdown(f"""
        <div class='kpi-card kpi-card-total'>
            <div class='kpi-value'>{total_sites}</div>
            <div class='kpi-label'>Total Sites</div>
        </div>
    """, unsafe_allow_html=True)

# KPI 2: Up Sites (Green)
with kpi_cols[1]:
    st.markdown(f"""
        <div class='kpi-card kpi-card-up'>
            <div class='kpi-value' style='color: var(--status-up) !important;'>{up_count}</div>
            <div class='kpi-label'>UP & Fast</div>
        </div>
    """, unsafe_allow_html=True)

# KPI 3: Slow Sites (Yellow)
with kpi_cols[2]:
    st.markdown(f"""
        <div class='kpi-card kpi-card-slow'>
            <div class='kpi-value' style='color: var(--status-warn) !important;'>{slow_count}</div>
            <div class='kpi-label'>UP (Slow)</div>
        </div>
    """, unsafe_allow_html=True)

# KPI 4: Down Sites (Red)
with kpi_cols[3]:
    st.markdown(f"""
        <div class='kpi-card kpi-card-down'>
            <div class='kpi-value' style='color: var(--status-down) !important;'>{down_count}</div>
            <div class='kpi-label'>DOWN / Error</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

# ==========================================================
# 1.5 CHATBOT WINDOW (New Placement near SYSTEM HEALTH OVERVIEW)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>DIAGNOSTIC AI: ORSA-AI</h2>", unsafe_allow_html=True)

bot_col, chat_col = st.columns([1, 3])

with bot_col:
    # --- Robot Animation ---
    if robot_lottie:
        # Reduced height for sticky/compact look
        streamlit_lottie(robot_lottie, height=120, key="robot_lottie_main") 
    else:
        st.markdown("<h1 style='text-align: center;'>👩‍💻</h1>", unsafe_allow_html=True)
    st.markdown(f"<h3 style='text-align: center; margin-top:-10px;'>ORSA-AI</h3>", unsafe_allow_html=True)
    st.caption("Ask me anything about a site's status.", unsafe_allow_html=True)

with chat_col:
    # --- Chat History Display ---
    with st.container(height=250, border=True):
        if not st.session_state.chat_history:
            st.session_state.chat_history.append({"role": "assistant", "content": "Hello! I am ORSA-AI. I monitor your systems. Ask me about a site, like: **'Why is Odisha Map Server down?'**"})
        
        for message in st.session_state.chat_history:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
    
    # --- Chat Input ---
    site_names_list = df['Website Name'].unique().tolist()
    
    prompt = st.chat_input("Ask me about a site...", key="chat_input_main")
    
    if prompt:
        if df.empty:
            st.session_state.chat_history.append({"role": "assistant", "content": "SYSTEM OFFLINE: Data is not loaded yet. Please wait for the first monitoring run."})
            st.rerun()
        
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        
        df_latest = load_data().sort_values("DateTime", ascending=False).drop_duplicates(subset=["Website Name"], keep="first").reset_index(drop=True)
        
        site_match = next((name for name in site_names_list if name.lower() in prompt.lower()), None)
        
        if site_match:
            response = analyze_downtime(
                site_match, 
                df_latest, 
                RESPONSE_TIME_THRESHOLD, 
                SSL_ALERT_DAYS
            )
        elif "thank" in prompt.lower() or "bye" in prompt.lower():
            response = "You're welcome! I am here 24/7 if you need further analysis. BEEP BOOP! (Jumping off now)"
        elif "sites" in prompt.lower() or "list" in prompt.lower():
            response = "BEEP! I am currently monitoring these sites: **" + ", ".join(site_names_list) + "**"
        else:
            response = "BEEP! I did not recognize the site name. Try: **" + site_names_list[0] + "** or **" + site_names_list[-1] + "**."

        st.session_state.chat_history.append({"role": "assistant", "content": response})
        st.rerun()


st.markdown("---")


# ==========================================================
# 2. LATEST MONITORING SNAPSHOT (Compact Table with Badges)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>LATEST MONITORING SNAPSHOT (Compact)</h2>", unsafe_allow_html=True)

# Download button for the snapshot data
snapshot_csv = convert_df_to_csv(df_latest)
st.download_button(
    label="⬇️ Download Snapshot Data (CSV)",
    data=snapshot_csv,
    file_name=f'orsac_snapshot_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
    mime='text/csv',
    key='download_snapshot_button'
)

# Define the highly compact columns for the latest status (UPDATED to use TTFB/TLS)
snapshot_cols = [c for c in [
    "Website Name", "Status", "Sensitive", "Confirmed Down", "Suspect", 
    "Ping (ms)", "TLS Handshake (ms)", "HTTP TTFB (ms)", "SSL Days Left", "Keyword Check" # Keyword Check added back
] if c in df_latest.columns]

# Prepare the data frame
df_snapshot = df_latest[snapshot_cols].copy()

# Helper to format SSL Days Left as a clean integer string
def format_ssl_days(x):
    val = safe_float_or_none(x)
    if val is not None and not pd.isna(val):
        return str(int(val))
    return str(x).strip()

if "SSL Days Left" in df_snapshot.columns:
    df_snapshot["SSL Days Left"] = df_snapshot["SSL Days Left"].apply(format_ssl_days)
    
# Format ms values (Ping/TLS/TTFB)
df_snapshot = format_numeric_columns(df_snapshot, ["Ping (ms)", "TLS Handshake (ms)", "HTTP TTFB (ms)"])

# Rename columns for clarity in the snapshot view
df_snapshot = df_snapshot.rename(columns={
    "Website Name": "Site",
    "Ping (ms)": "Ping (ms)",
    "TLS Handshake (ms)": "TLS (ms)", # Use shorter name for compact table
    "HTTP TTFB (ms)": "TTFB (ms)", # Use shorter name for compact table
    "SSL Days Left": "SSL Days"
})

# Render the snapshot table with badges
render_table_with_badges(df_snapshot, title="") # Pass empty title since we use markdown <h2>
st.markdown("---")


# ==========================================================
# 3. DETAILED EVENT LOG (Paginated Table)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>DETAILED EVENT LOG</h2>", unsafe_allow_html=True) # Changed title slightly for clarity

# Get all log data sorted by time
df_log = df.sort_values("DateTime", ascending=False).copy()
TOTAL_LOG_ROWS = len(df_log)
MAX_PAGES = math.ceil(TOTAL_LOG_ROWS / LOG_PAGE_SIZE)
current_page = st.session_state.event_log_page

# Calculate start and end indices for slicing (Moved up to fix NameError)
start_idx = current_page * LOG_PAGE_SIZE
end_idx = start_idx + LOG_PAGE_SIZE
end_idx = min(end_idx, TOTAL_LOG_ROWS)

# Add download button for the full log here
download_log_col, _ = st.columns([0.25, 0.75])
with download_log_col:
    st.download_button(
        label=f"⬇️ Download Full Log ({TOTAL_LOG_ROWS} rows)",
        data=convert_df_to_csv(df_log),
        file_name=f'orsac_monitor_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
        mime='text/csv',
        key='download_full_log'
    )
st.markdown(f"<p style='font-size: 14px; margin-top: 10px; color: var(--text-secondary);'>Showing entries {start_idx + 1} to {end_idx} of {TOTAL_LOG_ROWS}</p>", unsafe_allow_html=True)


# Slice the data to get the current page's entries
last_n = df_log.iloc[start_idx:end_idx].copy()

# New list of all performance metrics for formatting
perf_metrics_cols = [
    "Ping (ms)", "TCP Connect (ms)", "TLS Handshake (ms)", 
    "DNS Time (ms)", "HTTP TTFB (ms)", "HTTP FirstChunk (ms)", 
    "HTTP Total (ms)", "Content Size (KB)", "Redirects"
]

# Format numeric columns (leaving 'Failed' as strings)
last_n = format_numeric_columns(last_n, perf_metrics_cols)

# Only process "SSL Days Left" here
for col in ["SSL Days Left"]:
    if col in last_n.columns:
        # Convert numeric expiry fields to strings for table (otherwise pandas auto-formats 0 to 0.0)
        last_n[col] = last_n[col].apply(lambda x: str(int(safe_float_or_none(x))) if pd.notna(safe_float_or_none(x)) else str(x).strip())

# Enrich last_n with site-level flags
last_n["Website Name"] = last_n["Website Name"].astype(str)
last_n["Sensitive"] = last_n["Website Name"].apply(lambda n: bool((sites_map.get(n) or {}).get("sensitive", False)))
last_n["Alert Sent"] = last_n["Website Name"].apply(lambda n: bool(_get_state(n, "alert_sent", False)))
last_n["Consecutive Failures"] = last_n["Website Name"].apply(lambda n: int(_get_state(n, "consecutive_failures", 0) or 0))
last_n["Down Since"] = last_n["Website Name"].apply(lambda n: _get_state(n, "down_since", None))
last_n["Confirmed Down"] = last_n["Alert Sent"]
last_n["Suspect"] = last_n["Consecutive Failures"].apply(lambda x: x > 0 and x < 3)

# Choose display columns (monitoring relevant, plus badges) - UPDATED TO INCLUDE NEW PHASES
# Keyword Check added back to display
display_cols = [c for c in [
    "DateTime", "Website Name", "URL", "Sensitive", "Status", "Confirmed Down", "Suspect",
    "Ping (ms)", "DNS Time (ms)", "TCP Connect (ms)", "TLS Handshake (ms)", # Order changed for flow
    "HTTP TTFB (ms)", "HTTP FirstChunk (ms)", "HTTP Total (ms)",
    "Redirects", "Keyword Check", "SSL Days Left", "SSL Expiry Date", "Notes"
] if c in last_n.columns]

last_n = last_n[display_cols].copy()

# Render as HTML table with badges
render_table_with_badges(last_n, title="") 

# Pagination Controls
log_nav_cols = st.columns([1, 1, 6, 1, 1])

with log_nav_cols[1]:
    if st.button("Previous", disabled=current_page == 0, key="prev_log"):
        st.session_state.event_log_page -= 1
        st.rerun()

with log_nav_cols[3]:
    if st.button("Next", disabled=current_page >= MAX_PAGES - 1, key="next_log"):
        st.session_state.event_log_page += 1
        st.rerun()

st.markdown("---")

# ==========================================================
# 4. PERFORMANCE CHARTS (Metrics Separated and Stacked Vertically)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>PERFORMANCE TIMES (ms) — LATEST SNAPSHOT</h2>", unsafe_allow_html=True)

site_names = df_latest["Website Name"].astype(str).tolist()

def get_series_data(metric_name, color):
    data_points = []
    for _, row in df_latest.iterrows():
        # IMPORTANT: Use safe_float_or_none to convert failure strings ('Failed', 'N/A') to None,
        # which ECharts plots correctly as a break/gap in the line.
        value = safe_float_or_none(row.get(metric_name))
        data_points.append(value)
    return data_points

# --- Ping Time (Mandatory Ping Check) ---
ping_data = get_series_data("Ping (ms)", "#007BFF")
st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
st.caption("Ping Time (ms) per Site (ICMP Check)")
ping_options = create_line_chart_options("Ping (ms)", ping_data, "#007BFF", site_names, y_name="Time (ms)")
st_echarts(options=sanitize_for_json(ping_options), height="300px")
st.markdown("</div>", unsafe_allow_html=True)

# --- DNS Time ---
dns_data = get_series_data("DNS Time (ms)", "#17A2B8")
st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
st.caption("DNS Resolution Time (ms)")
dns_options = create_line_chart_options("DNS Time (ms)", dns_data, "#17A2B8", site_names, y_name="Time (ms)")
st_echarts(options=sanitize_for_json(dns_options), height="300px")
st.markdown("</div>", unsafe_allow_html=True)

# --- TCP Connect Time ---
tcp_data = get_series_data("TCP Connect (ms)", "#28A745")
st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
st.caption("TCP Connect Latency (ms)")
tcp_options = create_line_chart_options("TCP Connect (ms)", tcp_data, "#28A745", site_names, y_name="Time (ms)")
st_echarts(options=sanitize_for_json(tcp_options), height="300px")
st.markdown("</div>", unsafe_allow_html=True)

# --- TLS Handshake Time (NEW) ---
if "TLS Handshake (ms)" in df_latest.columns:
    tls_data = get_series_data("TLS Handshake (ms)", "#6C757D")
    st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
    st.caption("TLS Handshake Time (ms)")
    tls_options = create_line_chart_options("TLS Handshake (ms)", tls_data, "#6C757D", site_names, y_name="Time (ms)")
    st_echarts(options=sanitize_for_json(tls_options), height="300px")
    st.markdown("</div>", unsafe_allow_html=True)

# --- HTTP TTFB Time (NEW - Replaces general HTTP Time) ---
if "HTTP TTFB (ms)" in df_latest.columns:
    ttfb_data = get_series_data("HTTP TTFB (ms)", "#007BFF")
    st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
    st.caption(f"HTTP TTFB (Time To First Byte) (ms) (Threshold: {RESPONSE_TIME_THRESHOLD}ms)")
    ttfb_options = create_line_chart_options("HTTP TTFB (ms)", ttfb_data, "#007BFF", site_names, y_name="Time (ms)", threshold=RESPONSE_TIME_THRESHOLD)
    st_echarts(options=sanitize_for_json(ttfb_options), height="300px")
    st.markdown("</div>", unsafe_allow_html=True)

# --- HTTP FirstChunk Time (NEW) ---
if "HTTP FirstChunk (ms)" in df_latest.columns:
    first_chunk_data = get_series_data("HTTP FirstChunk (ms)", "#17A2B8")
    st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
    st.caption("HTTP First Chunk Transfer Time (ms)")
    first_chunk_options = create_line_chart_options("HTTP FirstChunk (ms)", first_chunk_data, "#17A2B8", site_names, y_name="Time (ms)")
    st_echarts(options=sanitize_for_json(first_chunk_options), height="300px")
    st.markdown("</div>", unsafe_allow_html=True)

# --- HTTP Total Time (NEW) ---
if "HTTP Total (ms)" in df_latest.columns:
    total_data = get_series_data("HTTP Total (ms)", "#28A745")
    st.markdown("<div class='chart-container'>", unsafe_allow_html=True)
    st.caption("HTTP Total Transfer Time (ms)")
    total_options = create_line_chart_options("HTTP Total (ms)", total_data, "#28A745", site_names, y_name="Time (ms)")
    st_echarts(options=sanitize_for_json(total_options), height="300px")
    st.markdown("</div>", unsafe_allow_html=True)


st.markdown("---")

# ==========================================================
# 5. EXPIRY CHARTS (Line Charts Separated)
# ==========================================================
st.markdown("<h2 class='futuristic-sub'>CERTIFICATE EXPIRY STATUS</h2>", unsafe_allow_html=True)

# --- SSL Expiry Chart ---
ssl_data = get_series_data("SSL Days Left", "#DC3545")
st.caption(f"SSL Days Left per Site (Warning Threshold: {SSL_ALERT_DAYS} days)")
ssl_options = create_line_chart_options("SSL Days Left", ssl_data, "#DC3545", site_names, y_name="Days Left", threshold=SSL_ALERT_DAYS)
st_echarts(options=sanitize_for_json(ssl_options), height="300px")

st.markdown("---")
st.caption("Status Colors: Green (🟢) = Up, Amber (🟡) = Slow/Warning, Red (🔴) = Down/Error. Chart lines show individual site metrics clearly.")
