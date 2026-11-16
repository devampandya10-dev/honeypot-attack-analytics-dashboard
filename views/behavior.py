"""
views/behavior.py — Command & Behavior Analysis (Page 5)
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from utils.ui import demo_banner, section, C, base_layout, AXIS_STYLE, legend_style, COMMAND_CATEGORY_COLORS
from utils.data_loader import is_demo_mode


def _categorise(cmd: str) -> str:
    c = str(cmd).lower()
    if any(k in c for k in ["wget", "curl", "tftp", "ftpget", "http://"]):
        return "Malware Download"
    elif any(k in c for k in ["chmod", "./", "sh ", "bash", "python", "perl"]):
        return "Script Execution"
    elif any(k in c for k in ["uname", "cpuinfo", "issue", "whoami", "id", "/etc/passwd"]):
        return "System Discovery"
    elif any(k in c for k in ["grep", "ps ", "ps -", "top", "miner"]):
        return "Process Discovery"
    elif any(k in c for k in ["ifconfig", "cloud print", "route", "netstat", "ip "]):
        return "Network Recon"
    elif any(k in c for k in ["history", "rm ", "clear"]):
        return "Anti-Forensics"
    elif any(k in c for k in ["ls", "cat ", "echo"]):
        return "File / Config Discovery"
    return "Other"


def render(data: dict):
    commands = data["commands"]

    st.markdown("## ⌨️ Command & Behavior Analysis")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Post-authentication attacker telemetry — interactive shell commands executed inside the honeypot session.</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if is_demo_mode():
        demo_banner()

    if commands.empty:
        st.info("ℹ️ No command input events (`cowrie.command.input`) present in current dataset.")
        return

    # Categorise
    commands = commands.copy()
    commands["category"] = commands["command"].apply(_categorise)
    top_cmd = commands["command"].mode()[0] if not commands.empty else "—"
    top_cat = commands["category"].mode()[0] if not commands.empty else "—"
    ip_col = "src_ip_identifier" if "src_ip_identifier" in commands.columns else "source_ip"
    unique_executors = commands[ip_col].nunique()

    # ── KPI cards ─────────────────────────────────────────────────────────────
    section("Command Execution Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Command Executions",  f"{len(commands):,}")
    c2.metric("Unique Commands",     commands["command"].nunique())
    c3.metric("Attackers in Shell",   unique_executors)
    c4.metric("Dominant Category",   top_cat)

    # ── Top commands + categories ─────────────────────────────────────────────
    col1, col2 = st.columns([2, 1])

    with col1:
        section("Most Executed Commands")
        top = commands["command"].value_counts().head(12).reset_index()
        top.columns = ["command", "count"]
        top["display_cmd"] = top["command"].apply(lambda x: f"{x[:40]}..." if len(str(x)) > 42 else str(x))

        fig1 = px.bar(
            top, x="count", y="display_cmd", orientation="h",
            color="count",
            color_continuous_scale=[[0, "#2e1a4a"], [1, C["purple"]]],
            custom_data=["command", "count"],
            labels={"display_cmd": "Command", "count": "Executions"},
        )
        fig1.update_traces(
            hovertemplate="<b>%{customdata[0]}</b><br>Executions: %{customdata[1]:,}<extra></extra>"
        )
        fig1.update_layout(
            **base_layout(height=320),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Executions"),
            yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
        )
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        section("Command Intent Categories")
        cat_counts = commands["category"].value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        cat_colors = [COMMAND_CATEGORY_COLORS.get(cat, C["muted"]) for cat in cat_counts["category"]]
        fig2 = go.Figure(go.Pie(
            labels=cat_counts["category"],
            values=cat_counts["count"],
            hole=0.5,
            marker=dict(colors=cat_colors),
            textinfo="percent",
            textposition="inside",
            hovertemplate="<b>%{label}</b><br>Executions: %{value:,}<br>Share: %{percent}<extra></extra>",
            textfont=dict(size=11),
        ))
        fig2.update_layout(
            **base_layout(height=320),
            showlegend=True,
            legend=legend_style(orientation="v", font=dict(size=10)),
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Commands over time ─────────────────────────────────────────────────────
    section("Command Activity Over Time")
    span = commands["timestamp"].max() - commands["timestamp"].min()
    freq = "h" if span <= pd.Timedelta(days=2) else "D"
    lbl = "Hourly" if freq == "h" else "Daily"

    cmd_ts = (
        commands.groupby([pd.Grouper(key="timestamp", freq=freq), "category"])
        .size().reset_index(name="count")
    )
    fig3 = px.area(
        cmd_ts, x="timestamp", y="count", color="category",
        color_discrete_map=COMMAND_CATEGORY_COLORS,
        labels={"timestamp": "", "count": f"Commands ({lbl})", "category": "Category"},
    )
    fig3.update_layout(
        **base_layout(height=240),
        xaxis=dict(**AXIS_STYLE, title=""),
        yaxis=dict(**AXIS_STYLE, title=f"Commands ({lbl})"),
        legend=legend_style(orientation="h", yanchor="bottom", y=1.02),
    )
    st.plotly_chart(fig3, use_container_width=True)

    # ── Command log ───────────────────────────────────────────────────────────
    section("Command Log")
    c_col = "country_name" if "country_name" in commands.columns else "country"
    display = commands.sort_values("timestamp", ascending=False).head(20).copy()
    display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    display["Attacker"] = display[ip_col].apply(lambda x: f"{x[:12]}..." if len(str(x)) > 16 else str(x))
    display["Country"] = display[c_col].fillna("Unknown")

    st.dataframe(
        display[["timestamp", "Attacker", "Country", "command", "category"]].rename(columns={
            "timestamp": "Timestamp (UTC)",
            "command": "Executed Command",
            "category": "Classification",
        }),
        use_container_width=True, height=260, hide_index=True,
    )

    # ── Attack behavior sequence ──────────────────────────────────────────────
    section("Typical Attack Lifecycle")
    st.markdown("""
    <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;
                padding:18px 22px;line-height:2.0;font-size:13px;color:#c9d1d9;margin-bottom:10px;">
        <span style="color:#58a6ff;font-weight:600;">① TCP Connection (cowrie.session.connect)</span>
        &nbsp;→&nbsp;
        <span style="color:#f0883e;font-weight:600;">② Brute Force (cowrie.login.failed)</span>
        &nbsp;→&nbsp;
        <span style="color:#3fb950;font-weight:600;">③ Authentication Success (cowrie.login.success)</span>
        &nbsp;→&nbsp;
        <span style="color:#bc8cff;font-weight:600;">④ Interactive Shell (cowrie.command.input)</span>
        &nbsp;→&nbsp;
        <span style="color:#f85149;font-weight:600;">⑤ Session Teardown (cowrie.session.closed)</span>
    </div>
    """, unsafe_allow_html=True)
    st.caption(
        "ℹ️ **Lifecycle Note:** This lifecycle illustrates the sequence of stages when an attacker advances through an entire session. "
        "It represents a possible progression observed in honeypot telemetry rather than a mandatory path; "
        "the vast majority of sessions terminate during initial brute-force attempts and do not reach the post-exploitation or command stages."
    )
