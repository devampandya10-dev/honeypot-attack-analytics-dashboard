"""
app.py — Honeypot Attack Analytics Dashboard
Entry point. Run with:  streamlit run app.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import streamlit as st
from utils.data_loader import load_data, get_data_mode_label, is_demo_mode

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Honeypot Analytics",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Base */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

.stApp                 { background-color: #0d1117; }
section[data-testid="stSidebar"]       { background-color: #0d1117; border-right: 1px solid #21262d; }
[data-testid="stSidebarContent"]       { padding: 1.25rem 1rem; }

/* Remove default top padding */
.block-container { padding-top: 1.5rem !important; }

/* Radio nav items */
div[data-testid="stRadio"] label {
    background: transparent !important;
    color: #8b949e !important;
    padding: 6px 10px !important;
    border-radius: 6px !important;
    font-size: 13.5px !important;
    display: block;
    transition: all .15s;
}
div[data-testid="stRadio"] label:hover       { background: #161b22 !important; color: #e6edf3 !important; }
div[data-testid="stRadio"] [aria-checked="true"] + div label { 
    background: #161b22 !important; color: #58a6ff !important; font-weight: 500 !important;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 14px 18px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.2);
    transition: border-color .15s ease, transform .15s ease;
}
[data-testid="stMetric"]:hover {
    border-color: #30363d;
}
[data-testid="stMetricLabel"]  { color: #8b949e !important; font-size: 11.5px !important; text-transform: uppercase; letter-spacing: .6px; font-weight: 500; }
[data-testid="stMetricValue"]  { color: #e6edf3 !important; font-size: 26px !important; font-weight: 600 !important; letter-spacing: -0.3px; }

/* Tabs */
button[data-baseweb="tab"] {
    font-size: 13px !important;
    font-weight: 500 !important;
    color: #8b949e !important;
    padding: 8px 16px !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #58a6ff !important;
    border-bottom-color: #58a6ff !important;
}

/* Dataframe & Tables */
[data-testid="stDataFrame"] {
    border: 1px solid #21262d;
    border-radius: 8px;
    overflow: hidden;
}

/* Divider */
hr { border-color: #21262d !important; margin: 1.25rem 0 !important; }

/* Scrollbar */
::-webkit-scrollbar       { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

/* Headings & Text */
h1, h2, h3 { color: #e6edf3 !important; letter-spacing: -0.2px; }
h4, h5, h6 { color: #c9d1d9 !important; }
p, li       { color: #c9d1d9; font-size: 13.5px; }
code {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 2px 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    color: #58a6ff;
}
</style>
""", unsafe_allow_html=True)

from utils.data_loader import load_data, is_demo_mode, set_data_mode

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    # Brand
    st.markdown("""
    <div style="text-align:center; padding: 8px 0 20px 0;">
        <div style="font-size:30px;">🍯</div>
        <div style="font-size:15px; font-weight:700; color:#e6edf3; margin-top:4px; letter-spacing:.3px;">
            HONEYPOT ANALYTICS
        </div>
        <div style="font-size:11px; color:#6e7681; margin-top:2px; letter-spacing:.5px;">
            THREAT INTELLIGENCE DASHBOARD
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Navigation
    st.markdown('<p style="font-size:11px;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Navigation</p>', unsafe_allow_html=True)

    NAV_ICONS = {
        "Security Overview":        "🏠",
        "Attackers":                "👤",
        "Attack Timeline":          "📈",
        "Credential Attacks":       "🔑",
        "Command & Behavior":       "⌨️",
        "Geography":                "🌍",
        "Anomaly Detection":        "🤖",
    }
    page = st.radio(
        "",
        list(NAV_ICONS.keys()),
        format_func=lambda x: f"  {NAV_ICONS[x]}  {x}",
        label_visibility="collapsed",
    )

    st.markdown("---")

    # Data mode selector
    st.markdown('<p style="font-size:11px;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">Data Source</p>', unsafe_allow_html=True)
    mode_selection = st.radio(
        "Data Mode",
        ["REAL DATA (CyberLab)", "DEMO DATA (Synthetic)"],
        index=0,
        label_visibility="collapsed",
    )
    is_real = mode_selection.startswith("REAL")
    set_data_mode("real" if is_real else "demo")

    if is_real:
        st.markdown("""
        <div style="background:#1c2128;border:1px solid #3fb95044;border-radius:6px;
                    padding:8px 12px;font-size:12px;color:#3fb950;font-weight:600;
                    text-align:center;letter-spacing:.5px;">
            ✅  REAL DATA
        </div>
        <p style="font-size:11px;color:#6e7681;margin-top:6px;text-align:center;">
            CyberLab Cowrie Capture<br>1,374,742 events · 284,918 sessions
        </p>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:#1c2128;border:1px solid #f0883e44;border-radius:6px;
                    padding:8px 12px;font-size:12px;color:#f0883e;font-weight:600;
                    text-align:center;letter-spacing:.5px;">
            ⚠️  DEMO DATA
        </div>
        <p style="font-size:11px;color:#6e7681;margin-top:6px;text-align:center;">
            Synthetic mock dataset (400 events).
        </p>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown(f'<p style="font-size:10px;color:#6e7681;text-align:center;">Stage 2D · Real Data Connected</p>', unsafe_allow_html=True)

# ── Load data (cached by mode) ────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def _load_data_cached(mode_key: str):
    return load_data(mode=mode_key)

data = _load_data_cached("real" if is_real else "demo")

import views.overview
import views.attackers
import views.timeline
import views.credentials
import views.behavior
import views.geography
import views.anomalies

# ── Route to page ─────────────────────────────────────────────────────────────
if page == "Security Overview":
    views.overview.render(data)
elif page == "Attackers":
    views.attackers.render(data)
elif page == "Attack Timeline":
    views.timeline.render(data)
elif page == "Credential Attacks":
    views.credentials.render(data)
elif page == "Command & Behavior":
    views.behavior.render(data)
elif page == "Geography":
    views.geography.render(data)
elif page == "Anomaly Detection":
    views.anomalies.render(data)
