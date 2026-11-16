"""
views/timeline.py — Attack Timeline & Session Behavioral Analytics (Page 3)
Stage 3A: Enhanced with Session Duration, Outcomes, and Temporal Progression Analytics.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np

from utils.ui import demo_banner, section, C, base_layout, AXIS_STYLE, legend_style, EVENT_TYPE_COLORS
from utils.data_loader import is_demo_mode


def render(data: dict):
    events   = data["events"]
    sessions = data.get("sessions", pd.DataFrame())

    st.markdown("## 📈 Attack Timeline & Session Analytics")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Temporal event progression, hourly distributions, and session duration & behavioral lifecycle analytics.</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if is_demo_mode():
        demo_banner()

    ev_col = "eventid" if "eventid" in events.columns else "event_type"

    # Determine observed time range accurately
    t_min = events["timestamp"].min()
    t_max = events["timestamp"].max()
    time_span = t_max - t_min
    observed_hours = time_span.total_seconds() / 3600

    # ── KPI cards: Event Summary ──────────────────────────────────────────────
    section("Event Temporal Summary")
    # Hour-of-day distribution (across all event timestamps, any date)
    hourly_hod = events.groupby(events["timestamp"].dt.hour).size()
    peak_hour = f"{int(hourly_hod.idxmax()):02d}:00 UTC" if not hourly_hod.empty else "—"
    # Avg per hour calculated from observed time range, not padded to 24
    avg_per_hour = round(len(events) / observed_hours, 1) if observed_hours > 0 else 0

    # Peak day: use calendar date grouping (includes Sat if events exist)
    daily_counts = events.groupby(events["timestamp"].dt.date).size()
    peak_day = str(daily_counts.idxmax()) if not daily_counts.empty else "—"

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events",      f"{len(events):,}")
    c2.metric("Peak Activity Day", peak_day)
    c3.metric("Peak Event Hour",   peak_hour)
    c4.metric("Avg Events / Hour", f"{avg_per_hour:,.0f}", f"over {observed_hours:.1f}h observed")

    # ── Granularity selector + main chart ─────────────────────────────────────
    section("Events Over Time")
    # Always offer hourly for datasets <= 2 days; daily/weekly for longer
    is_short_span = time_span <= pd.Timedelta(days=2)
    if is_short_span:
        options = ["Hourly", "30-Min", "15-Min"]
        freq_map = {"Hourly": "h", "30-Min": "30min", "15-Min": "15min"}
    else:
        options = ["Hourly", "Daily", "Weekly"]
        freq_map = {"Hourly": "h", "Daily": "D", "Weekly": "W"}

    gran = st.radio(
        "Granularity", options,
        horizontal=True, label_visibility="collapsed",
    )
    freq = freq_map[gran]

    # Group by actual timestamps — include all buckets (Fri + Sat 00:xx)
    ts = (
        events.set_index("timestamp")[ev_col]
        .resample(freq).count()
        .reset_index()
        .rename(columns={"timestamp": "period", ev_col: "count"})
    )
    # Only keep buckets that actually contain events (drop empty resample padding)
    ts = ts[ts["count"] > 0]

    fig = go.Figure(go.Bar(
        x=ts["period"], y=ts["count"],
        marker_color=C["blue"], marker_line_width=0,
        opacity=0.85, name="Events",
        hovertemplate="<b>%{x|%Y-%m-%d %H:%M UTC}</b><br>Events: %{y:,}<extra></extra>",
    ))
    fig.update_layout(
        **base_layout(height=300),
        xaxis=dict(**AXIS_STYLE, title=""),
        yaxis=dict(**AXIS_STYLE, title="Events"),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Row 2: by hour-of-day + by weekday ───────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        section("Events by Hour of Day (UTC)")
        # Aggregate across all calendar dates — hour 0 on Saturday counts too
        by_hour = (
            events.groupby(events["timestamp"].dt.hour)
            .size().reset_index(name="count")
        )
        by_hour.columns = ["hour", "count"]
        fig2 = px.bar(
            by_hour, x="hour", y="count",
            color="count",
            color_continuous_scale=[[0, "#1a3a5c"], [1, C["blue"]]],
            labels={"hour": "Hour (UTC)", "count": "Events"},
        )
        fig2.update_traces(hovertemplate="<b>%{x:02d}:00 UTC</b><br>Events: %{y:,}<extra></extra>")
        fig2.update_layout(
            **base_layout(height=260),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Hour of Day (UTC) — all observed dates", tickmode="linear", dtick=4),
            yaxis=dict(**AXIS_STYLE, title="Events"),
        )
        st.plotly_chart(fig2, use_container_width=True)

    with col2:
        section("Events by Day of Week")
        day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        # Use actual calendar dates — no filtering by threshold, include all days with events
        by_dow = (
            events.assign(weekday=events["timestamp"].dt.day_name())
            .groupby("weekday").size().reset_index(name="count")
        )
        present_days = [d for d in day_order if d in by_dow["weekday"].values]
        by_dow["weekday"] = pd.Categorical(by_dow["weekday"], categories=present_days, ordered=True)
        by_dow = by_dow.sort_values("weekday")
        fig3 = px.bar(
            by_dow, x="weekday", y="count",
            color="count",
            color_continuous_scale=[[0, "#5a2e0a"], [1, C["orange"]]],
            labels={"weekday": "", "count": "Events"},
        )
        fig3.update_traces(hovertemplate="<b>%{x}</b><br>Events: %{y:,}<extra></extra>")
        fig3.update_layout(
            **base_layout(height=260),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="", type="category"),
            yaxis=dict(**AXIS_STYLE, title="Events"),
        )
        st.plotly_chart(fig3, use_container_width=True)

    # ── Stacked area: event types over time ───────────────────────────────────
    section("Event Type Breakdown Over Time")
    top_types = events[ev_col].value_counts().head(5).index.tolist()
    events_filtered = events[events[ev_col].isin(top_types)]

    area_freq = "h" if is_short_span else "D"
    et_ts = (
        events_filtered.groupby([pd.Grouper(key="timestamp", freq=area_freq), ev_col])
        .size().reset_index(name="count")
    )
    # Keep only non-empty buckets
    et_ts = et_ts[et_ts["count"] > 0]

    fig4 = px.area(
        et_ts, x="timestamp", y="count", color=ev_col,
        color_discrete_map=EVENT_TYPE_COLORS,
        labels={"timestamp": "", "count": "Events", ev_col: "Event Type"},
    )
    fig4.update_layout(
        **base_layout(height=260),
        xaxis=dict(**AXIS_STYLE, title=""),
        yaxis=dict(**AXIS_STYLE, title="Events"),
        legend=legend_style(orientation="h", yanchor="bottom", y=1.02),
    )
    st.plotly_chart(fig4, use_container_width=True)

    # ── Hour × Day heatmap ────────────────────────────────────────────────────
    section("Event Intensity Heatmap (Hour × Day of Week)")
    pivot = (
        events.groupby([
            events["timestamp"].dt.day_name().rename("weekday"),
            events["timestamp"].dt.hour.rename("hour"),
        ])
        .size()
        .reset_index(name="count")
    )
    # Use all days actually present — no pre-filtering
    all_days = [d for d in day_order if d in pivot["weekday"].unique()]
    pivot["weekday"] = pd.Categorical(pivot["weekday"], categories=all_days, ordered=True)
    pivot = pivot.sort_values("weekday")

    # Data-driven colour range: zmin=0 reserved for empty cells (bg colour),
    # the nonzero range maps from a visible mid-tone to the brightest accent.
    z_max = int(pivot["count"].max())
    fig5 = go.Figure(go.Heatmap(
        x=pivot["hour"],
        y=pivot["weekday"],
        z=pivot["count"],
        zmin=0,
        zmax=z_max,
        colorscale=[
            [0,    "#161b22"],   # 0 events → background (invisible, correct for empty)
            [0.01, "#1a3a5c"],   # nonzero floor → clearly visible dark-blue
            [0.5,  C["blue"]],   # mid-range → bright blue
            [1,    C["red"]],    # max → red
        ],
        hoverongaps=False,
        xgap=2, ygap=2,
        hovertemplate="<b>%{y}, %{x:02d}:00 UTC</b><br>Events: %{z:,}<extra></extra>",
    ))
    fig5.update_layout(
        **base_layout(height=240),
        xaxis=dict(title="Hour of Day (UTC)", tickmode="linear", dtick=4,
                   gridcolor=C["border"], linecolor=C["border"]),
        yaxis=dict(title="", gridcolor=C["border"], linecolor=C["border"], type="category"),
    )
    st.plotly_chart(fig5, use_container_width=True)

    # ── Session Behavioral Analytics ──────────────────────────────────────────
    st.markdown("---")
    st.markdown("### ⏱️ Session Behavioral Analytics")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Empirical session duration profiles, lifecycle event densities, and authentication outcome distributions.</p>",
        unsafe_allow_html=True,
    )

    if sessions.empty:
        st.info("ℹ️ No session data available in current mode.")
        return

    total_sessions = len(sessions)

    # Duration calculations (filtering valid non-negative durations)
    if "duration" in sessions.columns:
        valid_dur = sessions["duration"].dropna()
        valid_dur = valid_dur[valid_dur >= 0]
        valid_count = len(valid_dur)
        excluded_count = total_sessions - valid_count
        med_dur = float(valid_dur.median()) if not valid_dur.empty else 0.0
        p95_dur = float(valid_dur.quantile(0.95)) if not valid_dur.empty else 0.0
    else:
        valid_dur = pd.Series(dtype=float)
        valid_count = 0
        excluded_count = total_sessions
        med_dur = 0.0
        p95_dur = 0.0

    # Session-level outcome counts — derived from sessions.parquet, not event counts
    has_fail = sessions["failed_logins"] > 0 if "failed_logins" in sessions.columns else pd.Series(False, index=sessions.index)
    has_succ = sessions["successful_logins"] > 0 if "successful_logins" in sessions.columns else pd.Series(False, index=sessions.index)
    sess_fail = int(has_fail.sum())
    sess_succ = int(has_succ.sum())
    sess_cmds = int((sessions["command_count"] > 0).sum()) if "command_count" in sessions.columns else 0

    sess_fail_only = int((has_fail & ~has_succ).sum())
    sess_succ_only = int((~has_fail & has_succ).sum())
    sess_both = int((has_fail & has_succ).sum())
    sess_auth = int((has_fail | has_succ).sum())

    # ── Session KPI cards ─────────────────────────────────────────────────────
    section("Session Overview & Lifespan KPIs")
    s1, s2, s3, s4, s5, s6 = st.columns(6)
    s1.metric("Total Sessions", f"{total_sessions:,}")
    s2.metric("Median Duration", f"{med_dur:.2f}s")
    s3.metric("95th %ile Duration", f"{p95_dur:.2f}s")
    s4.metric("Sessions w/ Auth Attempts", f"{sess_auth:,}", f"{sess_auth/total_sessions*100:.1f}%")
    s5.metric("Sessions w/ Successful Login", f"{sess_succ:,}", f"{sess_succ/total_sessions*100:.2f}%")
    s6.metric("Sessions w/ Commands", f"{sess_cmds:,}", f"{sess_cmds/total_sessions*100:.2f}%")

    st.caption(
        f"ℹ️ **Session Metrics Note:** All session counts are derived from sessions.parquet (session-level aggregates), "
        f"not individual event records. Auth activity = {sess_auth:,} sessions with any authentication activity "
        f"({sess_fail_only:,} with failed attempts only; {sess_succ_only:,} with successful attempts only; {sess_both:,} with both). "
        f"Duration statistics cover {valid_count:,} of {total_sessions:,} sessions with valid termination timestamps. "
        f"{excluded_count:,} sessions had no recorded connection-close timestamp and are excluded from duration stats."
    )

    # ── Session Distribution Charts ───────────────────────────────────────────
    col_s1, col_s2 = st.columns(2)

    with col_s1:
        section("Session Duration Distribution")
        if not valid_dur.empty:
            bins = [0, 1, 3, 5, 10, 30, 60, 120, np.inf]
            labels = ["< 1s", "1–3s", "3–5s", "5–10s", "10–30s", "30–60s", "60–120s", "> 120s"]
            binned = pd.cut(valid_dur, bins=bins, labels=labels, right=False)
            dist = binned.value_counts(sort=False).reset_index()
            dist.columns = ["duration_bracket", "count"]
            dist["pct"] = (dist["count"] / valid_count) * 100

            fig_dur = px.bar(
                dist, x="count", y="duration_bracket", orientation="h",
                color="count",
                color_continuous_scale=[[0, "#1a3a5c"], [1, C["blue"]]],
                custom_data=["duration_bracket", "count", "pct"],
                labels={"duration_bracket": "Duration", "count": "Sessions"},
            )
            fig_dur.update_traces(
                hovertemplate="<b>Bracket: %{customdata[0]}</b><br>Sessions: %{customdata[1]:,}<br>Share: %{customdata[2]:.2f}%<extra></extra>"
            )
            fig_dur.update_layout(
                **base_layout(height=280),
                coloraxis_showscale=False,
                xaxis=dict(**AXIS_STYLE, title="Sessions"),
                yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
            )
            st.plotly_chart(fig_dur, use_container_width=True)
            # Verify bins sum
            bin_total = dist["count"].sum()
            if bin_total != valid_count:
                st.caption(f"⚠️ Bin total ({bin_total:,}) differs from valid sample ({valid_count:,}).")
        else:
            st.caption("Duration data not available.")

    with col_s2:
        section("Event Density per Session")
        if "event_count" in sessions.columns:
            # Neutral labels — no inferred intent
            ev_bins = [1, 2, 4, 6, 10, np.inf]
            ev_labels = ["1 event", "2–3 events", "4–5 events", "6–9 events", "10+ events"]
            binned_ev = pd.cut(sessions["event_count"], bins=ev_bins, labels=ev_labels, right=False)
            ev_dist = binned_ev.value_counts(sort=False).reset_index()
            ev_dist.columns = ["events_bracket", "count"]
            ev_dist["pct"] = (ev_dist["count"] / total_sessions) * 100

            fig_ev = px.bar(
                ev_dist, x="count", y="events_bracket", orientation="h",
                color="count",
                color_continuous_scale=[[0, "#5a2e0a"], [1, C["orange"]]],
                custom_data=["events_bracket", "count", "pct"],
                labels={"events_bracket": "Events per Session", "count": "Sessions"},
            )
            fig_ev.update_traces(
                hovertemplate="<b>%{customdata[0]}</b><br>Sessions: %{customdata[1]:,}<br>Share: %{customdata[2]:.2f}%<extra></extra>"
            )
            fig_ev.update_layout(
                **base_layout(height=280),
                coloraxis_showscale=False,
                xaxis=dict(**AXIS_STYLE, title="Sessions"),
                yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
            )
            st.plotly_chart(fig_ev, use_container_width=True)
        else:
            st.caption("Event count data not available.")

    # ── Session Findings Section ──────────────────────────────────────────────
    section("Session Behavioral Findings")
    pct_under_5s = (valid_dur < 5).sum() / valid_count * 100 if valid_count > 0 else 0
    pct_4_5_ev = ev_dist[ev_dist["events_bracket"] == "4–5 events"]["pct"].values[0] if "event_count" in sessions.columns and len(ev_dist) > 0 else 0
    st.markdown(f"""
    <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:18px 22px;font-size:13px;line-height:1.8;color:#c9d1d9;">
        <strong style="color:#58a6ff;">1. Short Session Duration:</strong> Median session duration is <strong>{med_dur:.2f} seconds</strong> (95th percentile: <strong>{p95_dur:.2f} seconds</strong>). <strong>{pct_under_5s:.1f}%</strong> of the {valid_count:,} sessions with valid duration end within 5 seconds. The prevalence of very short sessions may indicate automated tooling, though session duration alone is not conclusive evidence of attacker intent.<br>
        <strong style="color:#f0883e;">2. 4–5 Event Sessions Dominate:</strong> <strong>{pct_4_5_ev:.1f}%</strong> of all {total_sessions:,} sessions contain exactly 4–5 events. This pattern closely matches the typical sequence of a minimal SSH connection (connect → banner → key exchange → one auth attempt → close), consistent with what automated scanners might produce, but other explanations are possible.<br>
        <strong style="color:#3fb950;">3. Post-Authentication Funnel:</strong> <strong>{sess_auth/total_sessions*100:.1f}%</strong> ({sess_auth:,}) of sessions contain at least one authentication attempt. Of those, <strong>{sess_succ/total_sessions*100:.2f}%</strong> ({sess_succ:,} sessions) have at least one successful login, and <strong>{sess_cmds/total_sessions*100:.2f}%</strong> ({sess_cmds:,} sessions) contain at least one recorded shell command (command_count > 0).
    </div>
    """, unsafe_allow_html=True)
