"""
utils/ui.py — Shared UI building blocks for every dashboard page.

Key design decision
-------------------
PLOTLY_LAYOUT contains ONLY properties that never need to be overridden per-chart
(paper/plot bg, font, margin).  Axis and legend config are set per-chart so that
Plotly's update_layout() never receives the same keyword twice.
"""

import streamlit as st
import plotly.graph_objects as go

# ── Colour palette ─────────────────────────────────────────────────────────────
C = {
    "bg":      "#0d1117",
    "surface": "#161b22",
    "border":  "#21262d",
    "text":    "#e6edf3",
    "muted":   "#8b949e",
    "blue":    "#58a6ff",
    "green":   "#3fb950",
    "orange":  "#f0883e",
    "red":     "#f85149",
    "purple":  "#bc8cff",
    "teal":    "#39d353",
    "cyan":    "#38bdf8",
    "amber":   "#d29922",
    "pink":    "#f472b6",
}

# ── Shared Semantic & Categorical Colour Maps ──────────────────────────────────
# Fixed colour mapping for every honeypot event type across all views
EVENT_TYPE_COLORS = {
    "cowrie.session.connect":      "#58a6ff",  # Blue (session initiation)
    "cowrie.login.failed":        "#f85149",  # Red (auth failure)
    "cowrie.session.closed":       "#8b949e",  # Slate/Gray (session teardown)
    "cowrie.client.version":       "#38bdf8",  # Sky Blue (client version banner)
    "cowrie.client.kex":           "#bc8cff",  # Purple (key exchange)
    "cowrie.login.success":        "#3fb950",  # Green (auth success)
    "cowrie.direct-tcpip.request": "#f0883e",  # Orange (port forwarding/tunneling)
    "cowrie.command.input":        "#d29922",  # Amber/Gold (shell command execution)
    "cowrie.log.closed":           "#6e7681",  # Dark Muted
    "cowrie.client.fingerprint":   "#f472b6",  # Pink (hassh fingerprint)
    # Synthetic demo mode event types
    "login_attempt":               "#f85149",
    "login_success":               "#3fb950",
    "command":                     "#d29922",
    "session_start":               "#58a6ff",
    "session_end":                 "#8b949e",
}

# Fixed colour mapping for command categories across donut, legend, and timeline
COMMAND_CATEGORY_COLORS = {
    "Malware Download":       "#f85149",  # Red (high severity payload retrieval)
    "Script Execution":       "#f0883e",  # Orange (process/script execution)
    "System Discovery":       "#58a6ff",  # Blue (host/OS enumeration)
    "Process Discovery":      "#bc8cff",  # Purple (process listing/monitoring)
    "Network Recon":          "#2dd4bf",  # Teal (interface/route scanning)
    "Anti-Forensics":         "#f472b6",  # Pink (clearing history/logs)
    "File / Config Discovery": "#38bdf8",  # Cyan (file exploration)
    "Other":                  "#8b949e",  # Muted Gray (unclassified commands)
}

# Semantic outcome colours (Success / Failure)
OUTCOME_COLORS = {
    "Successful": "#3fb950",
    "Failed":     "#f85149",
    True:         "#3fb950",
    False:        "#f85149",
}

# Consistent sequential palettes for ranked bar charts on dark surface.
# IMPORTANT: floors must NOT be the same shade as the plot background (#161b22).
# A mid-tone floor guarantees every nonzero bar remains legible.
SEQUENTIAL_PALETTES = {
    "blue":   [[0, "#1a3a5c"], [1, C["blue"]]],
    "orange": [[0, "#5a2e0a"], [1, C["orange"]]],
    "red":    [[0, "#5a1a1a"], [1, C["red"]]],
    "purple": [[0, "#2e1a4a"], [1, C["purple"]]],
    "green":  [[0, "#0d3320"], [1, C["green"]]],
    "teal":   [[0, "#0d3030"], [1, C["teal"]]],
}

# Base layout — ONLY properties that are safe to include in every chart.
# Do NOT include legend, xaxis, yaxis here — those are set per-chart.
PLOTLY_BASE = dict(
    paper_bgcolor=C["bg"],
    plot_bgcolor=C["surface"],
    font=dict(color=C["text"], family="Inter, sans-serif", size=12),
    margin=dict(l=8, r=8, t=36, b=8),
)

# Standard axis style — import and unpack per-chart, do not share in PLOTLY_BASE
AXIS_STYLE = dict(gridcolor=C["border"], linecolor=C["border"], showgrid=True, zeroline=False)

def legend_style(**overrides) -> dict:
    """
    Return legend style dict, safely merging any overrides without duplicate keyword arguments.
    """
    style = dict(
        bgcolor="rgba(0,0,0,0)",
        bordercolor=C["border"],
        font=dict(size=11),
    )
    for k, v in overrides.items():
        if k == "font" and isinstance(v, dict):
            style["font"] = dict(style["font"], **v)
        else:
            style[k] = v
    return style


# Standard legend style
LEGEND_STYLE = legend_style()


def base_layout(**extra) -> dict:
    """
    Return a layout dict that is safe to pass as **kwargs to fig.update_layout().
    Callers may override any key by passing it as an extra kwarg.
    """
    layout = dict(**PLOTLY_BASE)
    layout.update(extra)
    return layout


# ── Reusable Streamlit components ──────────────────────────────────────────────

def page_header(title: str, subtitle: str = ""):
    st.markdown(f"## {title}")
    if subtitle:
        st.markdown(
            f'<p style="color:#8b949e;margin-top:-10px;font-size:14px;">{subtitle}</p>',
            unsafe_allow_html=True,
        )
    st.markdown("---")


def demo_banner():
    st.info(
        "**⚠️ DEMO DATA MODE** — All values are generated sample data for UI development only. "
        "They are **not** real honeypot observations. Connect the real dataset in Stage 2.",
        icon=None,
    )


def section(title: str):
    st.markdown(
        f'<p style="font-size:11px;color:#6e7681;text-transform:uppercase;'
        f'letter-spacing:1px;margin-top:22px;margin-bottom:6px;">{title}</p>',
        unsafe_allow_html=True,
    )


def coming_soon(label: str = ""):
    msg = f"<strong>{label}</strong> — " if label else ""
    st.markdown(
        f'<div style="background:#161b22;border:1px dashed #30363d;border-radius:8px;'
        f'padding:20px 24px;text-align:center;color:#6e7681;font-size:13px;line-height:1.6;">'
        f'{msg}Will be implemented in Stage 3 once the real dataset is connected.</div>',
        unsafe_allow_html=True,
    )


def kpi_row(metrics: list[tuple]):
    """
    Render a row of st.metric cards.
    metrics: list of (label, value) or (label, value, delta) tuples.
    """
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        if len(m) == 3:
            col.metric(m[0], m[1], m[2])
        else:
            col.metric(m[0], m[1])


def placeholder_chart(label: str, height: int = 300):
    """Styled empty chart with a centred message."""
    fig = go.Figure()
    fig.add_annotation(
        text=f"<b>{label}</b><br><span style='font-size:11px;'>"
             f"Chart will be built in Stage 3</span>",
        xref="paper", yref="paper", x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=14, color=C["muted"]),
        align="center",
    )
    fig.update_layout(
        **base_layout(height=height),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    st.plotly_chart(fig, use_container_width=True)
