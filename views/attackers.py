"""
views/attackers.py — Attackers (Page 2)
Stage 3A: Enhanced with Attacker Concentration (Pareto) & Authentication Outcome Analytics.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from utils.ui import demo_banner, section, C, base_layout, AXIS_STYLE, legend_style
from utils.data_loader import is_demo_mode


def render(data: dict):
    events    = data["events"]
    creds     = data["credentials"]
    attackers = data.get("attackers", pd.DataFrame())
    cmds      = data.get("commands", pd.DataFrame())

    st.markdown("## 👤 Attacker Analysis")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Behavioral profiling, activity concentration (Pareto distribution), and authentication outcomes of unique attacker identifiers.</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if is_demo_mode():
        demo_banner()

    ip_col = "src_ip_identifier" if "src_ip_identifier" in events.columns else "source_ip"
    country_col = "country_name" if "country_name" in events.columns else "country"

    # ── Normalize / Build Attacker DataFrame ──────────────────────────────────
    if not attackers.empty and "total_events" in attackers.columns:
        att_df = attackers.copy()
        # The user requested calculating first/last seen directly from event timestamps
        # rather than using the pre-aggregated values which may have used session boundaries.
        ev_ts = events.groupby(ip_col).agg(
            actual_first_seen=("timestamp", "min"),
            actual_last_seen=("timestamp", "max")
        ).reset_index()
        att_df = att_df.merge(ev_ts, left_on="src_ip_identifier", right_on=ip_col, how="left")
        att_df["first_seen"] = att_df["actual_first_seen"]
        att_df["last_seen"] = att_df["actual_last_seen"]
        att_df = att_df.drop(columns=["actual_first_seen", "actual_last_seen"])
    else:
        # Dynamic build for fallback or demo
        att_df = events.groupby(ip_col).agg(
            country_name=(country_col, "first"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            total_events=(ip_col, "count"),
        ).reset_index()
        att_df["src_ip_identifier"] = att_df[ip_col]
        att_df["total_sessions"] = 1

        c_ip = ip_col if ip_col in creds.columns else "source_ip"
        if not creds.empty:
            c_stats = creds.groupby(c_ip).agg(
                failed_logins=("login_success", lambda x: (x == False).sum()),
                successful_logins=("login_success", lambda x: (x == True).sum()),
            ).reset_index()
            att_df = att_df.merge(c_stats, left_on=ip_col, right_on=c_ip, how="left").fillna(0)
        else:
            att_df["failed_logins"] = 0
            att_df["successful_logins"] = 0

        cmd_ip = ip_col if ip_col in cmds.columns else "source_ip"
        if not cmds.empty:
            cmd_stats = cmds.groupby(cmd_ip).size().rename("total_commands").reset_index()
            att_df = att_df.merge(cmd_stats, left_on=ip_col, right_on=cmd_ip, how="left").fillna(0)
        else:
            att_df["total_commands"] = 0

    # Ensure command column exists
    if "total_commands" not in att_df.columns:
        att_df["total_commands"] = 0

    # ── KPI cards: Overview ───────────────────────────────────────────────────
    section("Attacker Overview")
    att_sorted = att_df.sort_values("total_events", ascending=False).reset_index(drop=True)
    total_attributed_events = int(att_df["total_events"].sum())
    unique_attackers = len(att_df)

    most_active_id = att_sorted.iloc[0]["src_ip_identifier"] if not att_sorted.empty else "—"
    most_active_count = int(att_sorted.iloc[0]["total_events"]) if not att_sorted.empty else 0
    avg_per_attacker = round(total_attributed_events / unique_attackers, 1) if unique_attackers else 0
    display_active = f"{most_active_id[:14]}..." if len(str(most_active_id)) > 16 else str(most_active_id)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Unique Attackers", f"{unique_attackers:,}")
    c2.metric("Most Active Attacker", display_active)
    c3.metric("Highest Event Count", f"{most_active_count:,}")
    c4.metric("Avg Events / Attacker", f"{avg_per_attacker:,}")

    # ── Attacker Activity Concentration (Pareto Analysis) ────────────────────
    section("Attacker Activity Concentration (Pareto Analysis)")

    top1_ev = most_active_count
    top1_pct = (top1_ev / total_attributed_events * 100) if total_attributed_events else 0

    top10_ev = int(att_sorted.iloc[:10]["total_events"].sum())
    top10_pct = (top10_ev / total_attributed_events * 100) if total_attributed_events else 0

    top20_ev = int(att_sorted.iloc[:20]["total_events"].sum())
    top20_pct = (top20_ev / total_attributed_events * 100) if total_attributed_events else 0

    tail_count = max(0, unique_attackers - 20)
    tail_ev = max(0, total_attributed_events - top20_ev)
    tail_pct = (tail_ev / total_attributed_events * 100) if total_attributed_events else 0

    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Top 1 Attacker Share", f"{top1_pct:.2f}%", f"{top1_ev:,} events")
    p2.metric("Top 10 Attackers Share", f"{top10_pct:.2f}%", f"{top10_ev:,} events")
    p3.metric("Top 20 Attackers Share", f"{top20_pct:.2f}%", f"{top20_ev:,} events")
    p4.metric(f"Tail Attackers ({tail_count:,})", f"{tail_pct:.2f}%", f"{tail_ev:,} events")

    # Pareto Chart: Top 20 Attackers
    top20 = att_sorted.iloc[:20].copy()
    top20["cum_events"] = top20["total_events"].cumsum()
    top20["cum_pct"] = (top20["cum_events"] / total_attributed_events * 100) if total_attributed_events else 0
    top20["display_id"] = top20["src_ip_identifier"].apply(lambda x: f"{x[:10]}..." if len(str(x)) > 12 else str(x))

    fig_pareto = go.Figure()
    fig_pareto.add_trace(go.Bar(
        x=top20["display_id"],
        y=top20["total_events"],
        name="Events",
        marker_color=C["blue"],
        customdata=list(zip(top20["src_ip_identifier"], top20["country_name"].fillna("Unknown"))),
        hovertemplate="<b>Attacker:</b> %{customdata[0]}<br><b>Country:</b> %{customdata[1]}<br><b>Events:</b> %{y:,}<extra></extra>",
    ))
    fig_pareto.add_trace(go.Scatter(
        x=top20["display_id"],
        y=top20["cum_pct"],
        name="Cumulative Share (%)",
        yaxis="y2",
        mode="lines+markers",
        line=dict(color=C["orange"], width=2.5),
        marker=dict(size=6, color=C["orange"]),
        hovertemplate="<b>Cumulative Share:</b> %{y:.2f}%<extra></extra>",
    ))
    fig_pareto.update_layout(
        **base_layout(height=340),
        xaxis=dict(**AXIS_STYLE, title="Top 20 Attacker Identifiers", tickangle=-35),
        yaxis=dict(**AXIS_STYLE, title="Event Count"),
        yaxis2=dict(
            title="Cumulative Share (%)",
            overlaying="y",
            side="right",
            range=[0, 100],
            tickmode="linear",
            dtick=20,
            showgrid=False,
            ticksuffix="%",
            linecolor=C["border"],
            tickfont=dict(color=C["orange"]),
        ),
        showlegend=True,
        legend=legend_style(orientation="h", yanchor="bottom", y=1.02),
    )
    st.plotly_chart(fig_pareto, use_container_width=True)

    # ── Authentication Outcomes by Attacker ───────────────────────────────────
    section("Authentication Outcomes by Attacker")

    attackers_fail = int((att_df["failed_logins"] > 0).sum())
    attackers_succ = int((att_df["successful_logins"] > 0).sum())
    attackers_cmds = int((att_df["total_commands"] > 0).sum())
    attackers_no_auth = int(((att_df["failed_logins"] == 0) & (att_df["successful_logins"] == 0)).sum())

    f1, f2, f3, f4 = st.columns(4)
    f1.metric("Attackers w/ Failed Login Attempts", f"{attackers_fail:,}", f"{attackers_fail/unique_attackers*100:.1f}% of attackers")
    f2.metric("Attackers w/ Successful Login", f"{attackers_succ:,}", f"{attackers_succ/unique_attackers*100:.1f}% of attackers")
    f3.metric("Attackers w/ Shell Commands", f"{attackers_cmds:,}", f"{attackers_cmds/unique_attackers*100:.1f}% of attackers")
    f4.metric("No Auth Attempts Recorded", f"{attackers_no_auth:,}", f"{attackers_no_auth/unique_attackers*100:.1f}% of attackers")

    st.caption(
        "ℹ️ **Category Definitions:** 'Attackers with Failed Login Attempts' = unique attackers where failed_logins > 0. "
        "'No Auth Attempts Recorded' = unique attackers where both failed_logins = 0 AND successful_logins = 0. "
        "These categories can overlap (e.g., an attacker may have both failed and successful logins). "
        "No authentication threshold or intent classification is applied; counts reflect observed event records only."
    )

    # ── Top Attackers by Event Volume ─────────────────────────────────────────
    section("Top Attackers by Event Volume")
    top_ips = att_sorted.head(12).copy()
    top_ips["country"] = top_ips["country_name"].fillna("Unknown")
    top_ips["display_id"] = top_ips["src_ip_identifier"].apply(lambda x: f"{x[:12]}..." if len(str(x)) > 16 else str(x))

    fig = px.bar(
        top_ips, x="total_events", y="display_id", orientation="h",
        color="total_events",
        color_continuous_scale=[[0, "#1a3a5c"], [1, C["blue"]]],
        custom_data=["src_ip_identifier", "country"],
        labels={"display_id": "Attacker", "total_events": "Events"},
    )
    fig.update_traces(
        hovertemplate="<b>Attacker ID:</b> %{customdata[0]}<br><b>Country:</b> %{customdata[1]}<br><b>Events:</b> %{x:,}<extra></extra>"
    )
    fig.update_layout(
        **base_layout(height=340),
        coloraxis_showscale=False,
        xaxis=dict(**AXIS_STYLE, title="Number of Events"),
        yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Attacker summary table ─────────────────────────────────────────────────
    section("Attacker Profile Summary Table")
    table = att_sorted.head(50).copy()
    first_s = table["first_seen"].dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3] if pd.api.types.is_datetime64_any_dtype(table["first_seen"]) else table["first_seen"]
    last_s = table["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3] if pd.api.types.is_datetime64_any_dtype(table["last_seen"]) else table["last_seen"]
    display_tbl = pd.DataFrame({
        "Attacker ID (short)": table["src_ip_identifier"].apply(lambda x: f"{x[:14]}…" if len(str(x)) > 16 else str(x)),
        "Full Attacker ID": table["src_ip_identifier"],
        "Country": table["country_name"].fillna("Unknown"),
        "First Seen (UTC)": first_s,
        "Last Seen (UTC)": last_s,
        "Total Events": table["total_events"],
        "Total Sessions": table["total_sessions"],
        "Failed Logins": table["failed_logins"],
        "Successful Logins": table["successful_logins"],
        "Total Commands": table["total_commands"],
    })
    st.dataframe(display_tbl.drop(columns=["Full Attacker ID"]), use_container_width=True, height=320, hide_index=True)

    # ── Attacker Deep Profile ─────────────────────────────────────────────────
    section("Attacker Deep Profile")
    top_candidates = display_tbl["Full Attacker ID"].tolist()
    if top_candidates:
        selected = st.selectbox("Select an Attacker Identifier to inspect profile", top_candidates)
        if selected:
            matching = display_tbl[display_tbl["Full Attacker ID"] == selected]
            if not matching.empty:
                row = matching.iloc[0]
                d1, d2, d3 = st.columns(3)
                d1.metric("Country",         str(row["Country"]))
                d2.metric("First Seen (UTC)", str(row["First Seen (UTC)"]))
                d3.metric("Last Seen (UTC)",  str(row["Last Seen (UTC)"]))

                d4, d5, d6, d7 = st.columns(4)
                d4.metric("Total Events",      f"{int(row['Total Events']):,}")
                d5.metric("Total Sessions",    f"{int(row['Total Sessions']):,}")
                d6.metric("Failed Logins",     f"{int(row['Failed Logins']):,}")
                d7.metric("Successful Logins", f"{int(row['Successful Logins']):,}")

                # Show matching commands if any
                if not cmds.empty:
                    c_ip = "src_ip_identifier" if "src_ip_identifier" in cmds.columns else "source_ip"
                    attacker_cmds = cmds[cmds[c_ip] == selected]
                    if not attacker_cmds.empty:
                        st.caption(f"Commands Executed by this Attacker ({len(attacker_cmds)})")
                        st.dataframe(
                            attacker_cmds[["timestamp", "command"]].rename(columns={"timestamp": "Time (UTC)", "command": "Executed Command"}),
                            use_container_width=True,
                            hide_index=True,
                        )
                    else:
                        st.caption("ℹ️ No interactive command inputs recorded for this attacker identifier.")

    # ── Analytical Findings ───────────────────────────────────────────────────
    section("Attacker Behavioral Findings")
    st.markdown(f"""
    <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:18px 22px;font-size:13px;line-height:1.8;color:#c9d1d9;">
        <strong style="color:#58a6ff;">1. Pareto Concentration:</strong> The top 10 most active attackers generate <strong>{top10_pct:.2f}%</strong> ({top10_ev:,} events) of total honeypot traffic, and the top 20 generate <strong>{top20_pct:.2f}%</strong> ({top20_ev:,} events). This highly concentrated activity suggests a small number of sources drive the majority of the scanning volume.<br>
        <strong style="color:#f0883e;">2. Asymmetric Exploitation Funnel:</strong> While <strong>{attackers_fail/unique_attackers*100:.1f}%</strong> ({attackers_fail:,}) of unique attackers actively attempted brute-force authentication, only <strong>{attackers_succ/unique_attackers*100:.1f}%</strong> ({attackers_succ:,}) succeeded in authenticating. Only <strong>{attackers_cmds/unique_attackers*100:.1f}%</strong> ({attackers_cmds:,}) entered post-compromise shell commands.<br>
        <strong style="color:#8b949e;">3. Reconnaissance Probing:</strong> <strong>{attackers_no_auth/unique_attackers*100:.1f}%</strong> ({attackers_no_auth:,}) of unique attackers disconnected immediately after TCP/SSH version exchange without issuing any authentication attempts, which may be consistent with mass IP scanning or banner-grabbing behavior.
    </div>
    """, unsafe_allow_html=True)
