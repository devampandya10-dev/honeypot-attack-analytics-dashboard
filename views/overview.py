"""
views/overview.py — Security Overview (Page 1)
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from utils.ui import demo_banner, section, C, base_layout, AXIS_STYLE, legend_style, EVENT_TYPE_COLORS, SEQUENTIAL_PALETTES
from utils.data_loader import is_demo_mode, get_data_mode_label


def render(data: dict):
    events      = data["events"]
    sessions    = data["sessions"]
    credentials = data["credentials"]

    # ── Header ────────────────────────────────────────────────────────────────
    col_title, col_badge = st.columns([5, 1])
    with col_title:
        st.markdown("## 🍯 Security Overview")
        st.markdown(
            '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
            "Honeypot telemetry — high-level overview of observed events, attacker sessions, and outcomes.</p>",
            unsafe_allow_html=True,
        )
    with col_badge:
        st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
        label = get_data_mode_label()
        color = "#f0883e" if is_demo_mode() else "#3fb950"
        st.markdown(
            f'<div style="border:1px solid {color}55;background:{color}11;border-radius:6px;'
            f'padding:6px 10px;font-size:11px;color:{color};font-weight:600;text-align:center;">'
            f'{label}</div>',
            unsafe_allow_html=True,
        )
    st.markdown("---")

    if is_demo_mode():
        demo_banner()
    else:
        st.markdown(
            '<div style="background:#161b22;border:1px solid #21262d;border-radius:6px;'
            'padding:8px 14px;font-size:12px;color:#8b949e;margin-bottom:12px;">'
            '📡 <strong>Active Telemetry Source:</strong> CyberLab Cowrie Honeypot Capture · '
            f'<strong>{len(events):,}</strong> total events across <strong>{len(sessions):,}</strong> sessions'
            '</div>',
            unsafe_allow_html=True,
        )

    # ── KPI cards ─────────────────────────────────────────────────────────────
    section("Key Metrics")
    total_events      = len(events)
    unique_attackers  = events["src_ip_identifier"].nunique() if "src_ip_identifier" in events.columns else events["source_ip"].nunique()
    total_sessions    = len(sessions)
    failed_logins     = int((credentials["login_success"] == False).sum()) if not credentials.empty else 0
    successful_logins = int((credentials["login_success"] == True).sum()) if not credentials.empty else 0
    
    country_col = "country_name" if "country_name" in events.columns else "country"
    valid_countries = events[country_col].dropna()
    valid_countries = valid_countries[~valid_countries.isin(["Unknown", "XX", ""])]
    countries_count = valid_countries.nunique()

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Total Events",       f"{total_events:,}")
    k2.metric("Unique Attackers",   f"{unique_attackers:,}")
    k3.metric("Total Sessions",     f"{total_sessions:,}")
    k4.metric("Failed Logins",      f"{failed_logins:,}")
    k5.metric("Successful Logins",  f"{successful_logins:,}")
    k6.metric("Countries Observed", f"{countries_count:,}")

    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

    # ── Row 1: Timeline + Event type donut ───────────────────────────────────
    section("Event Activity")
    col_left, col_right = st.columns([2, 1])

    with col_left:
        # Auto-detect resolution: hourly for <= 2 days, daily for longer
        time_span = events["timestamp"].max() - events["timestamp"].min()
        freq = "h" if time_span <= pd.Timedelta(days=2) else "D"
        freq_label = "Hourly" if freq == "h" else "Daily"
        st.caption(f"Activity Over Time ({freq_label})")

        ev_col = "eventid" if "eventid" in events.columns else "event_type"
        timeline_df = (
            events.set_index("timestamp")
            .resample(freq)[ev_col]
            .count()
            .reset_index()
            .rename(columns={"timestamp": "date", ev_col: "count"})
        )
        if freq == "h" and time_span <= pd.Timedelta(days=2):
            primary_date = events["timestamp"].min().date()
            overflow_mask = timeline_df["date"].dt.date > primary_date
            if overflow_mask.any():
                extra_cnt = timeline_df.loc[overflow_mask, "count"].sum()
                timeline_df = timeline_df.loc[~overflow_mask].copy()
                timeline_df.iloc[-1, timeline_df.columns.get_loc("count")] += extra_cnt

        fig = go.Figure(go.Scatter(
            x=timeline_df["date"], y=timeline_df["count"],
            mode="lines",
            line=dict(color=C["blue"], width=2),
            fill="tozeroy",
            fillcolor="rgba(88,166,255,0.15)",
            hovertemplate="<b>%{x|%Y-%m-%d %H:%M UTC}</b><br>Events: %{y:,}<extra></extra>",
            name="Events",
        ))
        fig.update_layout(
            **base_layout(height=260),
            xaxis=dict(**AXIS_STYLE, title=""),
            yaxis=dict(**AXIS_STYLE, title="Events"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.caption("Event Type Breakdown")
        ev_col = "eventid" if "eventid" in events.columns else "event_type"
        et = events[ev_col].value_counts().reset_index()
        et.columns = ["type", "count"]

        total_ev = et["count"].sum()
        shares = (et["count"] / total_ev) * 100
        text_labels = [f"{s:.1f}%" if s >= 4.0 else "" for s in shares]
        slice_colors = [EVENT_TYPE_COLORS.get(t, C["blue"]) for t in et["type"]]

        fig2 = go.Figure(go.Pie(
            labels=et["type"],
            values=et["count"],
            hole=0.55,
            text=text_labels,
            textinfo="text",
            textposition="inside",
            insidetextorientation="horizontal",
            hovertemplate="<b>%{label}</b><br>Events: %{value:,}<br>Share: %{percent}<extra></extra>",
            marker=dict(colors=slice_colors),
        ))
        fig2.update_layout(
            **base_layout(height=280, margin=dict(l=8, r=8, t=10, b=80)),
            showlegend=True,
            legend=legend_style(
                orientation="h",
                yanchor="top",
                y=-0.15,
                xanchor="center",
                x=0.5,
                font=dict(size=9.5),
            ),
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Row 2: Top Attackers + Top countries ─────────────────────────────────
    col_l2, col_r2 = st.columns(2)

    with col_l2:
        section("Top Attacker Identifiers")
        ip_col = "src_ip_identifier" if "src_ip_identifier" in events.columns else "source_ip"
        top_ips = (
            events.groupby([ip_col, country_col])
            .size()
            .reset_index(name="events")
            .sort_values("events", ascending=False)
            .head(8)
        )
        top_ips["display_id"] = top_ips[ip_col].apply(lambda x: f"{x[:12]}..." if len(str(x)) > 16 else str(x))
        fig3 = px.bar(
            top_ips, x="events", y="display_id", orientation="h",
            color="events",
            color_continuous_scale=[[0, "#1a3a5c"], [1, C["blue"]]],
            hover_data={ip_col: True, country_col: True, "display_id": False, "events": True},
            labels={"display_id": "Attacker", "events": "Events", ip_col: "Full ID", country_col: "Country"},
        )
        fig3.update_layout(
            **base_layout(height=280),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Events"),
            yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
        )
        st.plotly_chart(fig3, use_container_width=True)

    with col_r2:
        section("Activity by Country")
        by_country = valid_countries.value_counts().head(8).reset_index()
        by_country.columns = ["country", "count"]
        fig4 = px.bar(
            by_country, x="count", y="country", orientation="h",
            color="count",
            color_continuous_scale=[[0, "#5a2e0a"], [1, C["orange"]]],
            labels={"country": "", "count": "Events"},
        )
        fig4.update_layout(
            **base_layout(height=280),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Events"),
            yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
        )
        st.plotly_chart(fig4, use_container_width=True)

    # ── Recent events ─────────────────────────────────────────────────────────
    section("Recent Honeypot Events")
    ip_col = "src_ip_identifier" if "src_ip_identifier" in events.columns else "source_ip"
    ev_col = "eventid" if "eventid" in events.columns else "event_type"
    recent = events.sort_values("timestamp", ascending=False).head(10).copy()
    recent["timestamp"] = recent["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3]
    # Shorten attacker ID for display
    recent["Attacker ID"] = recent[ip_col].apply(lambda x: f"{str(x)[:14]}…" if len(str(x)) > 16 else str(x))
    # Replace None / NaN protocol and username with em dash
    recent["protocol"] = recent["protocol"].fillna("—").replace("None", "—").replace("", "—")
    recent["username"] = recent["username"].fillna("—").replace("None", "—").replace("", "—")

    cols_map = {
        "timestamp": "Timestamp (UTC)",
        "Attacker ID": "Attacker ID",
        country_col: "Country",
        ev_col: "Event Type",
        "protocol": "Protocol",
        "username": "Username",
    }
    show_cols = ["timestamp", "Attacker ID"] + [c for c in [country_col, ev_col, "protocol", "username"] if c in recent.columns]
    st.dataframe(
        recent[show_cols].rename(columns=cols_map),
        use_container_width=True,
        height=280,
        hide_index=True,
    )
