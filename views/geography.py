"""
views/geography.py — Geographical Analysis (Page 6)
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from utils.ui import demo_banner, section, C, base_layout, AXIS_STYLE, legend_style
from utils.data_loader import is_demo_mode


def render(data: dict):
    events = data["events"]
    creds  = data["credentials"]

    st.markdown("## 🌍 Geographical Analysis")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Geographic source origin breakdown of observed honeypot traffic and authentication attempts.</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if is_demo_mode():
        demo_banner()

    c_col = "country_name" if "country_name" in events.columns else "country"
    cc_col = "country_code2" if "country_code2" in events.columns else "country_code"
    ip_col = "src_ip_identifier" if "src_ip_identifier" in events.columns else "source_ip"

    # Filter out missing or unresolvable country entries safely
    clean_events = events.dropna(subset=[c_col]).copy()
    clean_events = clean_events[~clean_events[c_col].isin(["Unknown", "XX", ""])]

    # ── Country aggregation ───────────────────────────────────────────────────
    by_country = (
        clean_events.groupby([c_col, cc_col], as_index=False)
        .agg(events=(ip_col, "count"), unique_ips=(ip_col, "nunique"))
        .sort_values("events", ascending=False)
    )

    # Successful logins per country
    c_cred = "country_name" if "country_name" in creds.columns else "country"
    if not creds.empty and c_cred in creds.columns:
        succ = (
            creds[creds["login_success"] == True]
            .groupby(c_cred).size().rename("successful_logins").reset_index()
        )
        by_country = by_country.merge(succ, left_on=c_col, right_on=c_cred, how="left").fillna(0)
        by_country["successful_logins"] = by_country["successful_logins"].astype(int)
    else:
        by_country["successful_logins"] = 0

    # ── KPI cards ─────────────────────────────────────────────────────────────
    section("Summary")
    total_events_all = len(events)
    geolocated_events = len(clean_events)
    ungeolocated_events = total_events_all - geolocated_events
    top_country = by_country.iloc[0][c_col] if not by_country.empty else "—"
    countries_count = len(by_country)
    # Attackers with valid geolocation
    att = data.get("attackers", pd.DataFrame())
    if not att.empty and cc_col in att.columns:
        geo_att = att[att[cc_col].notna() & ~att[cc_col].isin(["XX", "", "unknown", "Unknown"])]
        unique_geo_attackers = len(geo_att)
        no_geo_attackers = len(att) - unique_geo_attackers
    else:
        unique_geo_attackers = clean_events[ip_col].nunique()
        no_geo_attackers = 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Countries Observed",    countries_count)
    c2.metric("Top Attacking Country", top_country)
    c3.metric("Geolocated Attackers",  f"{unique_geo_attackers:,}")
    c4.metric("Attackers w/o Geo",     f"{no_geo_attackers:,}")

    st.caption(
        f"ℹ️ **Coverage Note:** {geolocated_events:,} of {total_events_all:,} events have a resolvable country. "
        f"{ungeolocated_events:,} events have missing or unresolvable geolocation and are excluded from country charts. "
        f"All percentages below are of geolocated events only."
    )

    # ── Bar chart + donut ─────────────────────────────────────────────────────
    col1, col2 = st.columns([3, 2])

    with col1:
        section("Geolocated Event Volume by Country (Top 10)")

        top_10 = by_country.head(10)
        fig1 = px.bar(
            top_10, x="events", y=c_col, orientation="h",
            color="events",
            color_continuous_scale=[[0, "#5a2e0a"], [1, C["orange"]]],
            labels={c_col: "", "events": "Events"},
        )
        fig1.update_traces(
            hovertemplate="<b>%{y}</b><br>Events: %{x:,}<extra></extra>"
        )
        fig1.update_layout(
            **base_layout(height=320),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Events"),
            yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
        )
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        section("Traffic Share by Country")
        # Top 8 countries + group other for a readable donut
        top_8 = by_country.head(8).copy()
        other_events = by_country.iloc[8:]["events"].sum() if len(by_country) > 8 else 0
        if other_events > 0:
            top_8 = pd.concat([
                top_8,
                pd.DataFrame([{c_col: "Other Countries", "events": other_events}])
            ], ignore_index=True)

        fig2 = go.Figure(go.Pie(
            labels=top_8[c_col],
            values=top_8["events"],
            hole=0.5,
            textinfo="percent",
            textposition="inside",
            hovertemplate="<b>%{label}</b><br>Events: %{value:,}<br>Share: %{percent}<extra></extra>",
            marker=dict(colors=[
                C["blue"], C["orange"], C["green"], C["red"], C["purple"],
                C["teal"], "#79c0ff", "#ffa657", "#8b949e"
            ]),
            textfont=dict(size=11),
        ))
        fig2.update_layout(
            **base_layout(height=320),
            showlegend=True,
            legend=legend_style(orientation="v", font=dict(size=10)),
        )
        st.plotly_chart(fig2, use_container_width=True)

    # ── Country summary table ─────────────────────────────────────────────────
    section("Country Statistics Table")
    display = by_country.rename(columns={
        c_col: "Country",
        cc_col: "Country Code",
        "events": "Total Events",
        "unique_ips": "Unique Attackers",
        "successful_logins": "Successful Logins",
    })
    st.dataframe(
        display[["Country", "Country Code", "Total Events", "Unique Attackers", "Successful Logins"]],
        use_container_width=True,
        height=320,
        hide_index=True,
    )
