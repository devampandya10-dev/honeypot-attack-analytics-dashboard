"""
views/anomalies.py — Stage 5.1: Threat Investigation, Evidence Explorer & Explainable Severity Classification
Provides explainable rule-based threat detections, severity breakdown, interactive pattern drill-downs,
attacker/session searching and filtering, and full chronological session timeline reconstruction.
No machine learning models are used.
"""

import streamlit as st
import pandas as pd

from utils.ui import demo_banner, section, C, base_layout, AXIS_STYLE
from utils.data_loader import is_demo_mode, load_data, get_data_mode
from utils.detection_rules import run_all_detection_rules, mask_password


@st.cache_data(show_spinner="Evaluating detection rules and correlating incidents...")
def _cached_detection_pipeline(
    data_mode: str,
    thresh_failures: int,
    thresh_spray: int,
    thresh_reuse: int,
    thresh_window: int,
) -> dict:
    """Cached detection and incident correlation execution keyed by mode and thresholds.
    Loads data by mode internally to avoid repeatedly hashing large DataFrames as cache keys.
    """
    dataset = load_data(mode=data_mode)
    return run_all_detection_rules(
        sessions=dataset.get("sessions", pd.DataFrame()),
        credentials=dataset.get("credentials", pd.DataFrame()),
        commands=dataset.get("commands", pd.DataFrame()),
        threshold_failures=thresh_failures,
        threshold_distinct_usernames=thresh_spray,
        threshold_distinct_attackers=thresh_reuse,
        correlation_time_window_minutes=thresh_window,
    )


def render(data: dict):
    events = data["events"]
    sessions = data.get("sessions", pd.DataFrame())
    credentials = data.get("credentials", pd.DataFrame())
    commands = data.get("commands", pd.DataFrame())

    st.markdown("## 🛡️ Threat Detection & Severity Classification")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Deterministic, explainable threat candidate identification and severity classification derived from empirical honeypot telemetry. "
        "Flags candidate patterns without unsupervised ML or speculative scoring.</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if is_demo_mode():
        demo_banner()

    # ── Configurable Rule Thresholds (in one clean expander) ───────────────────
    with st.expander("⚙️ Detection Rule Configuration & Thresholds", expanded=False):
        st.markdown(
            '<p style="color:#8b949e;font-size:13px;">'
            "Thresholds determine the minimum observations required to flag candidate behavioral patterns. "
            "Adjusting thresholds dynamically recalculates all rule outputs, severity levels, and incident correlations.</p>",
            unsafe_allow_html=True,
        )
        t_col1, t_col2, t_col3, t_col4 = st.columns(4)
        with t_col1:
            thresh_failures = st.slider(
                "Rule A: Min Failures",
                min_value=3, max_value=30, value=10, step=1,
                help="Sessions with at least this many failed attempts are flagged as repeated failure candidates."
            )
        with t_col2:
            thresh_spray = st.slider(
                "Rule B: Min Usernames",
                min_value=2, max_value=20, value=5, step=1,
                help="Attacker IDs using the same password across at least this many distinct usernames are flagged as spraying candidates."
            )
        with t_col3:
            thresh_reuse = st.slider(
                "Rule C: Min Attackers",
                min_value=2, max_value=15, value=3, step=1,
                help="Identical (username, password) pairs observed across at least this many distinct attackers are flagged as reused."
            )
        with t_col4:
            thresh_window = st.slider(
                "Correlation Window (min)",
                min_value=5, max_value=120, value=30, step=5,
                help="Maximum elapsed time between consecutive findings for the same attacker to be grouped into the same incident (default: 30 minutes)."
            )

    # ── Execute Detection Rules (Cached by mode & thresholds) ──────────────────
    active_mode = "demo" if is_demo_mode() else "real"
    detection_results = _cached_detection_pipeline(
        data_mode=active_mode,
        thresh_failures=thresh_failures,
        thresh_spray=thresh_spray,
        thresh_reuse=thresh_reuse,
        thresh_window=thresh_window,
    )

    summary = detection_results["summary"]
    rules = detection_results["rules"]
    sev_counts = summary.get("severity_counts", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})

    # ── Top Summary KPIs ──────────────────────────────────────────────────────
    section("Detection Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Detection Rule Types", f"{summary['total_rules']}")
    c2.metric("Total Matched Patterns", f"{summary['total_matching_records']:,}")
    c3.metric("Unique Affected Attackers", f"{summary['unique_affected_attackers']:,}")
    c4.metric("Unique Affected Sessions", f"{summary['unique_affected_sessions']:,}")

    # ── Stage 5.1 Severity Breakdown ──────────────────────────────────────────
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    s_col1, s_col2, s_col3, s_col4 = st.columns(4)
    s_col1.metric("🔴 Critical Findings", f"{sev_counts['Critical']:,}", help="High-volume escalation (>= 3x threshold)")
    s_col2.metric("🟠 High Severity", f"{sev_counts['High']:,}", help="Escalated findings (>= 2x threshold)")
    s_col3.metric("🟡 Medium Severity", f"{sev_counts['Medium']:,}", help="Baseline threshold matches")
    s_col4.metric("🔵 Low Severity", f"{sev_counts['Low']:,}", help="Sub-threshold / informational")

    st.caption(
        "ℹ️ **Disaggregation Note:** 'Total Matched Patterns' sums candidate records across rules. "
        "'Unique Affected Attackers' and 'Sessions' deduplicate entities across rules, because a single attacker "
        "or session may trigger multiple independent rules. Severity levels are deterministic and explainable."
    )

    # ── Stage 5.2: Correlated Threat Incidents ─────────────────────────────────
    section("Correlated Threat Incidents")
    incidents = detection_results.get("incidents", [])
    incidents_df = detection_results.get("incidents_df", pd.DataFrame())
    inc_summary = detection_results.get("incident_summary", {})
    inc_sev_counts = inc_summary.get("severity_counts", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0})
    multi_inc_count = inc_summary.get("multi_finding_incidents", 0)

    # Incident KPIs
    i1, i2, i3, i4, i5 = st.columns(5)
    i1.metric("Total Correlated Incidents", f"{len(incidents):,}", help="Consolidated threat incidents grouped by session, attacker identifier, and time window")
    i2.metric("🔴 Critical Incidents", f"{inc_sev_counts.get('Critical', 0):,}")
    i3.metric("🟠 High Severity Incidents", f"{inc_sev_counts.get('High', 0):,}")
    i4.metric("🟡 Medium Severity Incidents", f"{inc_sev_counts.get('Medium', 0):,}")
    i5.metric("🔗 Multi-Finding Incidents", f"{multi_inc_count:,}", help="Incidents consolidating 2 or more distinct detection findings")

    st.markdown(
        f'<p style="color:#8b949e;font-size:13px;margin-top:-6px;">'
        f"Incident grouping correlates related detection findings sharing a session ID or occurring from the same attacker "
        f"within a <strong>{thresh_window}-minute</strong> activity window. Uncorrelated or isolated findings without reliable links remain separate.</p>",
        unsafe_allow_html=True,
    )

    if not incidents_df.empty:
        # Incident Filters
        f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
        with f_col1:
            sev_filter_inc = st.selectbox(
                "Filter Incidents by Severity:",
                ["All Severities", "Critical", "High", "Medium", "Low"],
                key="sev_inc_filter"
            )
        with f_col2:
            rule_options = [
                "All Rules",
                "Repeated Authentication Failures",
                "Password Spraying Candidates",
                "Credential Pair Reuse",
                "Authentication Success After Failures",
                "Post-Authentication Command Activity",
            ]
            rule_filter_inc = st.selectbox(
                "Filter by Detection Rule:",
                rule_options,
                key="rule_inc_filter"
            )
        with f_col3:
            search_inc = st.text_input(
                "🔍 Search Incidents (ID, Attacker, Session, Keyword):",
                key="search_inc_filter"
            ).strip()

        filtered_inc_df = incidents_df.copy()
        if sev_filter_inc != "All Severities":
            filtered_inc_df = filtered_inc_df[filtered_inc_df["Severity"] == sev_filter_inc]
        if rule_filter_inc != "All Rules":
            filtered_inc_df = filtered_inc_df[filtered_inc_df["Rules Involved"].str.contains(rule_filter_inc, case=False, na=False)]
        if search_inc:
            mask_search = (
                filtered_inc_df["Incident ID"].astype(str).str.contains(search_inc, case=False, na=False) |
                filtered_inc_df["Attacker Identifier"].astype(str).str.contains(search_inc, case=False, na=False) |
                filtered_inc_df["Session ID"].astype(str).str.contains(search_inc, case=False, na=False) |
                filtered_inc_df["Correlation Reason"].astype(str).str.contains(search_inc, case=False, na=False)
            )
            filtered_inc_df = filtered_inc_df[mask_search]

        disp_inc_cols = [
            "Incident ID", "Severity", "Rules Involved", "Findings Count",
            "Unique Attackers", "Attacker Identifier",
            "Unique Sessions", "Session ID",
            "First Seen (UTC)", "Last Seen (UTC)", "Correlation Reason"
        ]
        st.dataframe(filtered_inc_df[disp_inc_cols], use_container_width=True, hide_index=True, height=280)

        # ── Incident Deep-Dive & Findings Explorer ─────────────────────────────
        st.markdown("#### 🔬 Incident Deep-Dive & Associated Findings")
        st.markdown(
            '<p style="color:#8b949e;font-size:13px;margin-top:-8px;">'
            "Select an incident from the filtered candidates to inspect its constituent detection findings and timeline connections.</p>",
            unsafe_allow_html=True,
        )

        inc_id_options = filtered_inc_df["Incident ID"].tolist()
        if inc_id_options:
            selected_inc_id = st.selectbox(
                "Select Incident ID to inspect:",
                options=inc_id_options,
                index=0,
                key="select_inc_dropdown"
            )

            matching_inc = next((inc for inc in incidents if inc.incident_id == selected_inc_id), None)
            if matching_inc:
                sev_color = {
                    "Critical": "#f85149",
                    "High": "#f0883e",
                    "Medium": "#d29922",
                    "Low": "#58a6ff",
                }.get(matching_inc.severity, "#58a6ff")

                # ── Investigation Summary (Stage 5.3) ─────────────────────────
                rules_str = ", ".join(matching_inc.rules_involved) if matching_inc.rules_involved else "None"
                n_att = len(matching_inc.attacker_ids)
                n_sess = len(matching_inc.session_ids)
                att_desc = f"{n_att:,} attacker{'s' if n_att != 1 else ''}"
                sess_desc = f"{n_sess:,} session{'s' if n_sess != 1 else ''}"

                st.markdown(f"""
                <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {sev_color};border-radius:8px;padding:14px 18px;margin-bottom:12px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                        <span style="font-size:16px;font-weight:600;color:#c9d1d9;">Incident: <code>{matching_inc.incident_id}</code> &nbsp;
                            <span style="background:{sev_color}22;color:{sev_color};border:1px solid {sev_color}44;border-radius:4px;padding:2px 8px;font-size:12px;font-weight:bold;">{matching_inc.severity}</span>
                        </span>
                        <span style="font-size:12.5px;color:#8b949e;">Constituent Findings: <strong>{matching_inc.finding_count:,}</strong> &nbsp;|&nbsp; Observed: <strong>{matching_inc.first_seen}</strong> → <strong>{matching_inc.last_seen}</strong></span>
                    </div>
                    <div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px 14px;margin-top:6px;font-size:13px;line-height:1.7;color:#c9d1d9;">
                        <div style="font-weight:600;color:#58a6ff;margin-bottom:2px;">📋 Investigation Summary</div>
                        • <strong>Triggered Detection Rules:</strong> {rules_str}<br>
                        • <strong>Grouping & Correlation Rationale:</strong> {matching_inc.correlation_reason}<br>
                        • <strong>Severity Level:</strong> <span style="color:{sev_color};font-weight:600;">{matching_inc.severity}</span> ({matching_inc.severity_reason})<br>
                        • <strong>Timeline Interval:</strong> First seen <code>{matching_inc.first_seen}</code> UTC, last seen <code>{matching_inc.last_seen}</code> UTC<br>
                        • <strong>Associated Entities:</strong> {att_desc} and {sess_desc}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                findings_rows = []
                for f_idx, f in enumerate(matching_inc.findings):
                    f_st = f["first_seen"].strftime("%Y-%m-%d %H:%M:%S") if f["first_seen"] and pd.notna(f["first_seen"]) else "—"
                    f_et = f["last_seen"].strftime("%Y-%m-%d %H:%M:%S") if f["last_seen"] and pd.notna(f["last_seen"]) else "—"
                    f_row = {
                        "Finding #": f_idx + 1,
                        "Rule Name": f["rule_name"],
                        "Severity": f["severity"],
                        "Severity Reason": f["severity_reason"],
                        "Session ID": f["session_id"] or "—",
                        "Attacker Identifier": f["attacker_id"] or "—",
                        "First Seen (UTC)": f_st,
                        "Last Seen (UTC)": f_et,
                    }
                    for d_k, d_v in f.get("details", {}).items():
                        if d_k not in ["Severity", "Severity Reason", "Session ID", "Attacker Identifier", "Raw Password", "raw_password", "Detection Rule", "first_ts", "last_ts"]:
                            if "Password" in d_k or "password" in d_k or "pwd" in d_k.lower():
                                f_row[d_k] = mask_password(d_v)
                            else:
                                f_row[d_k] = d_v
                    findings_rows.append(f_row)

                if findings_rows:
                    st.dataframe(pd.DataFrame(findings_rows), use_container_width=True, hide_index=True)

                # Link to Timeline Explorer if sessions exist
                if matching_inc.session_ids:
                    s_links_col1, s_links_col2 = st.columns([1, 2])
                    with s_links_col1:
                        target_sid = st.selectbox(
                            "Associated Session ID:",
                            options=matching_inc.session_ids,
                            key=f"target_sid_{matching_inc.incident_id}"
                        )
                    with s_links_col2:
                        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
                        if st.button("🔎 Load Session in Timeline Explorer", key=f"btn_timeline_{matching_inc.incident_id}"):
                            st.session_state["timeline_sid_target"] = target_sid
                            st.rerun()
        else:
            st.caption("No incidents match the active severity or rule filter.")
    else:
        st.caption("No incidents detected under current threshold settings.")

    # ── Rule Selection / Tabs ─────────────────────────────────────────────────
    section("Rule Candidate Inspections")
    
    rule_tabs = st.tabs([
        f"Rule A: Repeated Failures ({rules['RULE_A'].matched_records_count:,})",
        f"Rule B: Password Spraying ({rules['RULE_B'].matched_records_count:,})",
        f"Rule C: Credential Reuse ({rules['RULE_C'].matched_records_count:,})",
        f"Rule D: Mixed Auth Outcomes ({rules['RULE_D'].matched_records_count:,})",
        f"Rule E: Post-Auth Commands ({rules['RULE_E'].matched_records_count:,})",
    ])

    ip_col = "src_ip_identifier" if "src_ip_identifier" in credentials.columns else "source_ip"
    has_sid = "session_id" in credentials.columns

    # ── TAB A: Repeated Authentication Failures ───────────────────────────────
    with rule_tabs[0]:
        ra = rules["RULE_A"]
        st.markdown(f"### 🔁 {ra.rule_name}")
        st.markdown(f"**Rule Condition:** `{ra.condition_description}`")
        
        m1, m2, m3 = st.columns(3)
        m1.metric("Matching Sessions", f"{ra.matched_records_count:,}")
        m2.metric("Unique Attackers", f"{ra.unique_affected_attackers:,}")
        m3.metric("Active Threshold", f">= {ra.threshold} failures")

        st.info(f"💡 **Analysis & Explanation:** {ra.explanation}")

        if not ra.evidence_df.empty:
            st.markdown("#### Candidate Sessions (Flagged Repeated Authentication Failures)")
            
            f_col1, f_col2 = st.columns([1, 2])
            with f_col1:
                sev_filter_a = st.selectbox(
                    "Filter by Severity:",
                    ["All Severities", "Critical", "High", "Medium", "Low"],
                    key="sev_ra"
                )
            with f_col2:
                search_a = st.text_input("🔍 Filter Rule A by Attacker Identifier or Session ID:", key="search_ra").strip()

            df_a = ra.evidence_df.copy()
            if sev_filter_a != "All Severities":
                df_a = df_a[df_a["Severity"] == sev_filter_a]
            if search_a:
                mask_a = (
                    df_a["Session ID"].astype(str).str.contains(search_a, case=False, na=False) |
                    df_a["Attacker Identifier"].astype(str).str.contains(search_a, case=False, na=False)
                )
                df_a = df_a[mask_a]

            disp_cols_a = [
                "Severity", "Severity Reason", "Session ID", "Attacker Identifier",
                "Failed Attempts", "Successful Logins", "Usernames Targeted",
                "Session Start (UTC)", "Session End (UTC)"
            ]
            st.dataframe(df_a[disp_cols_a], use_container_width=True, hide_index=True, height=280)
        else:
            st.caption("No records matched this rule threshold.")

    # ── TAB B: Password Spraying Candidates ───────────────────────────────────
    with rule_tabs[1]:
        rb = rules["RULE_B"]
        st.markdown(f"### 🌊 {rb.rule_name}")
        st.markdown(f"**Rule Condition:** `{rb.condition_description}`")

        m1, m2, m3 = st.columns(3)
        m1.metric("Spraying Patterns Flagged", f"{rb.matched_records_count:,}")
        m2.metric("Unique Attackers", f"{rb.unique_affected_attackers:,}")
        m3.metric("Active Threshold", f">= {rb.threshold} distinct users")

        st.info(f"💡 **Analysis & Explanation:** {rb.explanation}")

        if not rb.evidence_df.empty:
            st.markdown("#### Qualifying Attacker-Password Spraying Candidates")
            
            f_col1_b, f_col2_b = st.columns([1, 2])
            with f_col1_b:
                sev_filter_b = st.selectbox(
                    "Filter by Severity:",
                    ["All Severities", "High", "Medium"],
                    key="sev_rb"
                )
            with f_col2_b:
                search_b = st.text_input("🔍 Filter Rule B by Attacker Identifier or Masked Password:", key="search_rb").strip()

            df_b = rb.evidence_df.copy()
            if sev_filter_b != "All Severities":
                df_b = df_b[df_b["Severity"] == sev_filter_b]
            if search_b:
                mask_b = (
                    df_b["Attacker Identifier"].astype(str).str.contains(search_b, case=False, na=False) |
                    df_b["Masked Password"].astype(str).str.contains(search_b, case=False, na=False)
                )
                df_b = df_b[mask_b]

            disp_cols_b = [
                "Severity", "Severity Reason", "Attacker Identifier", "Masked Password",
                "Distinct Usernames", "Total Attempts", "Affected Sessions",
                "First Seen (UTC)", "Last Seen (UTC)"
            ]
            st.dataframe(df_b[disp_cols_b].head(100), use_container_width=True, hide_index=True, height=280)

            # Drill-down selector for Rule B
            st.markdown("##### 🔬 Evidence Drill-Down for Selected Spraying Pattern")
            candidates_b = df_b.head(50)
            if not candidates_b.empty:
                pat_options_b = [
                    f"[{r['Severity']}] {r['Attacker Identifier'][:14]}… | Pwd: {r['Masked Password']} ({r['Distinct Usernames']} users, {r['Affected Sessions']} sessions)"
                    for _, r in candidates_b.iterrows()
                ]
                sel_idx_b = st.selectbox(
                    "Select a qualifying spraying candidate to inspect exact usernames and sessions:",
                    range(len(pat_options_b)),
                    format_func=lambda i: pat_options_b[i],
                    key="sel_pat_b"
                )
                sel_row_b = candidates_b.iloc[sel_idx_b]
                sel_ip_b = sel_row_b["Attacker Identifier"]
                sel_pwd_raw_b = sel_row_b["Raw Password"]

                if not credentials.empty and has_sid:
                    q_creds_b = credentials[
                        (credentials[ip_col] == sel_ip_b) &
                        (credentials["password"].astype(str) == sel_pwd_raw_b)
                    ]
                    if not q_creds_b.empty:
                        c_b1, c_b2 = st.columns([1, 1])
                        with c_b1:
                            st.caption(f"Targeted Usernames ({q_creds_b['username'].nunique()} distinct)")
                            u_table_b = q_creds_b["username"].value_counts().reset_index()
                            u_table_b.columns = ["Username", "Attempts"]
                            st.dataframe(u_table_b, use_container_width=True, hide_index=True, height=200)
                        with c_b2:
                            st.caption(f"Affected Session IDs ({q_creds_b['session_id'].nunique()} unique)")
                            s_table_b = q_creds_b.groupby("session_id").agg(
                                attempts=("username", "count"),
                                first_seen=("timestamp", "min") if "timestamp" in q_creds_b.columns else ("username", "first")
                            ).reset_index().rename(columns={"session_id": "Session ID", "attempts": "Attempts", "first_seen": "Timestamp (UTC)"})
                            st.dataframe(s_table_b, use_container_width=True, hide_index=True, height=200)
        else:
            st.caption("No records matched this rule threshold.")

    # ── TAB C: Credential Pair Reuse ──────────────────────────────────────────
    with rule_tabs[2]:
        rc = rules["RULE_C"]
        st.markdown(f"### 🔗 {rc.rule_name}")
        st.markdown(f"**Rule Condition:** `{rc.condition_description}`")

        m1, m2, m3 = st.columns(3)
        m1.metric("Reused Credential Pairs", f"{rc.matched_records_count:,}")
        m2.metric("Attackers Observed Using Pairs", f"{rc.unique_affected_attackers:,}")
        m3.metric("Active Threshold", f">= {rc.threshold} distinct attackers")

        st.info(f"💡 **Analysis & Explanation:** {rc.explanation}")

        if not rc.evidence_df.empty:
            st.markdown("#### Qualifying Reused Credential Pairs")
            
            f_col1_c, f_col2_c = st.columns([1, 2])
            with f_col1_c:
                sev_filter_c = st.selectbox(
                    "Filter by Severity:",
                    ["All Severities", "High", "Medium"],
                    key="sev_rc"
                )
            with f_col2_c:
                search_c = st.text_input("🔍 Filter Rule C by Username or Masked Password:", key="search_rc").strip()

            df_c = rc.evidence_df.copy()
            if sev_filter_c != "All Severities":
                df_c = df_c[df_c["Severity"] == sev_filter_c]
            if search_c:
                mask_c = (
                    df_c["Username"].astype(str).str.contains(search_c, case=False, na=False) |
                    df_c["Masked Password"].astype(str).str.contains(search_c, case=False, na=False)
                )
                df_c = df_c[mask_c]

            disp_cols_c = [
                "Severity", "Severity Reason", "Username", "Masked Password",
                "Distinct Attackers", "Total Attempts", "Successful Logins", "Affected Sessions"
            ]
            st.dataframe(df_c[disp_cols_c].head(100), use_container_width=True, hide_index=True, height=280)

            # Drill-down selector for Rule C
            st.markdown("##### 🔬 Evidence Drill-Down for Selected Reused Credential Pair")
            candidates_c = df_c.head(50)
            if not candidates_c.empty:
                pat_options_c = [
                    f"[{r['Severity']}] User: {r['Username']} | Pwd: {r['Masked Password']} ({r['Distinct Attackers']} attackers, {r['Affected Sessions']} sessions)"
                    for _, r in candidates_c.iterrows()
                ]
                sel_idx_c = st.selectbox(
                    "Select a qualifying credential pair to inspect associated attackers and sessions:",
                    range(len(pat_options_c)),
                    format_func=lambda i: pat_options_c[i],
                    key="sel_pat_c"
                )
                sel_row_c = candidates_c.iloc[sel_idx_c]
                sel_user_c = sel_row_c["Username"]
                sel_pwd_raw_c = sel_row_c["Raw Password"]

                if not credentials.empty and has_sid:
                    q_creds_c = credentials[
                        (credentials["username"].astype(str) == sel_user_c) &
                        (credentials["password"].astype(str) == sel_pwd_raw_c)
                    ]
                    if not q_creds_c.empty:
                        c_c1, c_c2 = st.columns([1, 1])
                        with c_c1:
                            st.caption(f"Associated Attackers ({q_creds_c[ip_col].nunique()} distinct)")
                            att_table_c = q_creds_c.groupby(ip_col).agg(
                                attempts=("username", "count"),
                                country=("country_name", "first") if "country_name" in q_creds_c.columns else ("username", "first")
                            ).reset_index().rename(columns={ip_col: "Attacker Identifier", "attempts": "Attempts", "country": "Country"})
                            st.dataframe(att_table_c, use_container_width=True, hide_index=True, height=200)
                        with c_c2:
                            st.caption(f"Associated Sessions ({q_creds_c['session_id'].nunique()} unique)")
                            s_table_c = q_creds_c.groupby("session_id").agg(
                                attacker=(ip_col, "first"),
                                timestamp=("timestamp", "first") if "timestamp" in q_creds_c.columns else ("username", "first")
                            ).reset_index().rename(columns={"session_id": "Session ID", "attacker": "Attacker ID", "timestamp": "Timestamp (UTC)"})
                            st.dataframe(s_table_c, use_container_width=True, hide_index=True, height=200)
        else:
            st.caption("No records matched this rule threshold.")

    # ── TAB D: Authentication Success After Failures ──────────────────────────
    with rule_tabs[3]:
        rd = rules["RULE_D"]
        st.markdown(f"### ⚡ {rd.rule_name}")
        st.markdown(f"**Rule Condition:** `{rd.condition_description}`")

        m1, m2, m3 = st.columns(3)
        m1.metric("Matching Sessions", f"{rd.matched_records_count:,}")
        m2.metric("Unique Attackers", f"{rd.unique_affected_attackers:,}")
        m3.metric("Rule Evaluation", "Timestamp Progression Verified")

        st.info(f"💡 **Analysis & Explanation:** {rd.explanation}")

        if not rd.evidence_df.empty:
            st.markdown("#### Candidate Sessions (Mixed Authentication Progression)")
            
            f_col1_d, f_col2_d = st.columns([1, 2])
            with f_col1_d:
                sev_filter_d = st.selectbox(
                    "Filter by Severity:",
                    ["All Severities", "Medium"],
                    key="sev_rd"
                )
            with f_col2_d:
                search_d = st.text_input("🔍 Filter Rule D by Session ID or Attacker Identifier:", key="search_rd").strip()

            df_d = rd.evidence_df.copy()
            if sev_filter_d != "All Severities":
                df_d = df_d[df_d["Severity"] == sev_filter_d]
            if search_d:
                mask_d = (
                    df_d["Session ID"].astype(str).str.contains(search_d, case=False, na=False) |
                    df_d["Attacker Identifier"].astype(str).str.contains(search_d, case=False, na=False)
                )
                df_d = df_d[mask_d]

            disp_cols_d = [
                "Severity", "Severity Reason", "Session ID", "Attacker Identifier",
                "Failed Count", "Successful Count", "First Failure (UTC)",
                "First Success (UTC)", "Time Between Failure & Success", "Progression Status"
            ]
            st.dataframe(df_d[disp_cols_d], use_container_width=True, hide_index=True, height=280)
        else:
            st.caption("No records exhibited mixed authentication outcomes.")

    # ── TAB E: Post-Authentication Command Activity ───────────────────────────
    with rule_tabs[4]:
        re = rules["RULE_E"]
        st.markdown(f"### 💻 {re.rule_name}")
        st.markdown(f"**Rule Condition:** `{re.condition_description}`")

        m1, m2, m3 = st.columns(3)
        m1.metric("Sessions with Shell Activity", f"{re.matched_records_count:,}")
        m2.metric("Unique Attacker Identifiers", f"{re.unique_affected_attackers:,}")
        m3.metric("Interactive Shell Execution", "Post-Compromise Telemetry")

        st.info(f"💡 **Analysis & Explanation:** {re.explanation}")

        if not re.evidence_df.empty:
            st.markdown("#### Compromised Sessions Executing Commands")
            
            f_col1_e, f_col2_e = st.columns([1, 2])
            with f_col1_e:
                sev_filter_e = st.selectbox(
                    "Filter by Severity:",
                    ["All Severities", "Medium"],
                    key="sev_re"
                )
            with f_col2_e:
                search_e = st.text_input("🔍 Filter Rule E by Session ID, Attacker, or Command:", key="search_re").strip()

            df_e = re.evidence_df.copy()
            if sev_filter_e != "All Severities":
                df_e = df_e[df_e["Severity"] == sev_filter_e]
            if search_e:
                mask_e = (
                    df_e["Session ID"].astype(str).str.contains(search_e, case=False, na=False) |
                    df_e["Attacker Identifier"].astype(str).str.contains(search_e, case=False, na=False) |
                    df_e["Sample Commands"].astype(str).str.contains(search_e, case=False, na=False)
                )
                df_e = df_e[mask_e]

            disp_cols_e = [
                "Severity", "Severity Reason", "Session ID", "Attacker Identifier",
                "Successful Authentication (UTC)", "First Command (UTC)",
                "Delay to First Command", "Executed Commands", "Sample Commands", "Session Duration (s)"
            ]
            st.dataframe(df_e[disp_cols_e], use_container_width=True, hide_index=True, height=280)
        else:
            st.caption("No sessions recorded post-authentication commands.")

    # ── SECTION: Interactive Session Investigation Timeline ───────────────────
    section("Interactive Session Timeline Explorer")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-6px;font-size:13.5px;">'
        "Reconstruct the complete, granular chronological lifecycle for any investigated session ID "
        "(TCP connect &rarr; SSH version &rarr; key exchange &rarr; authentication &rarr; command inputs &rarr; teardown).</p>",
        unsafe_allow_html=True,
    )

    # Gather available session IDs for analyst selection
    sess_id_col = "session_id" if "session_id" in sessions.columns else "session_id"
    flagged_sessions = sorted(list(summary.get("all_affected_sessions", set()) or {
        str(sid) for sid in sessions[sess_id_col].dropna().head(100)
    }))

    col_srch1, col_srch2 = st.columns([2, 1])
    target_from_state = st.session_state.get("timeline_sid_target", "")
    with col_srch1:
        manual_sid = st.text_input("Enter or paste a Session ID to investigate:", value=target_from_state, placeholder="e.g. eadb4609049a, 8b731080a8db, 37ee23734070...").strip()
    with col_srch2:
        quick_select = st.selectbox(
            "Or select from prominent flagged sessions:",
            ["(None)"] + flagged_sessions[:100],
            index=0,
            key="quick_sess_select"
        )

    investigate_sid = manual_sid if manual_sid else (quick_select if quick_select != "(None)" else "")

    if investigate_sid:
        # Reconstruct events chronologically from events table
        sess_ev = events[events.get("session_id", pd.Series(dtype=str)) == investigate_sid].copy() if "session_id" in events.columns else pd.DataFrame()
        if sess_ev.empty:
            st.warning(f"⚠️ No granular event records found for Session ID `{investigate_sid}` in `events.parquet`.")
        else:
            sess_ev = sess_ev.sort_values("timestamp")
            att_id = sess_ev[ip_col].iloc[0] if ip_col in sess_ev.columns and pd.notna(sess_ev[ip_col].iloc[0]) else "Unknown"
            country = sess_ev.get("country_name", pd.Series(["Unknown"])).iloc[0]
            start_t = sess_ev["timestamp"].min()
            end_t = sess_ev["timestamp"].max()
            span_s = (end_t - start_t).total_seconds()

            st.markdown(f"""
            <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 18px;margin-bottom:12px;">
                <span style="color:#58a6ff;font-weight:600;">Session:</span> <code>{investigate_sid}</code> &nbsp;|&nbsp;
                <span style="color:#8b949e;">Attacker ID:</span> <code>{str(att_id)[:16]}…</code> &nbsp;|&nbsp;
                <span style="color:#8b949e;">Country:</span> <strong>{country}</strong> &nbsp;|&nbsp;
                <span style="color:#8b949e;">Span:</span> <strong>{span_s:.2f}s</strong> &nbsp;|&nbsp;
                <span style="color:#8b949e;">Total Events:</span> <strong>{len(sess_ev):,}</strong>
            </div>
            """, unsafe_allow_html=True)

            # Build readable chronological timeline records
            timeline_records = []
            for idx, r in sess_ev.iterrows():
                ev_id = r.get("eventid", r.get("event_type", "event"))
                ts_str = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if pd.api.types.is_datetime64_any_dtype(pd.Series([r["timestamp"]])) else str(r["timestamp"])

                if ev_id == "cowrie.session.connect":
                    desc = f"TCP connection established (protocol: {r.get('protocol', 'SSH')}, port: {r.get('src_port', '—')})"
                    stage = "🔌 Connection Init"
                elif ev_id == "cowrie.client.version":
                    desc = f"SSH version banner exchanged: {r.get('ssh_client_version', r.get('message', '—'))}"
                    stage = "🏷️ Banner Exchange"
                elif ev_id == "cowrie.client.kex":
                    desc = "Diffie-Hellman Key Exchange negotiated"
                    stage = "🔑 Key Exchange"
                elif ev_id == "cowrie.login.failed":
                    pwd_masked = mask_password(r.get('password', '—'))
                    desc = f"Authentication FAILED for username: '{r.get('username', '—')}' (password: {pwd_masked})"
                    stage = "❌ Login Failed"
                elif ev_id == "cowrie.login.success":
                    pwd_masked = mask_password(r.get('password', '—'))
                    desc = f"Authentication SUCCEEDED for username: '{r.get('username', '—')}' (password: {pwd_masked})"
                    stage = "✅ Login Succeeded"
                elif ev_id == "cowrie.command.input":
                    desc = f"Shell command executed: {r.get('message', r.get('command', '—'))}"
                    stage = "⌨️ Command Input"
                elif ev_id == "cowrie.direct-tcpip.request":
                    desc = f"Port forwarding / direct TCP request: {r.get('message', '—')}"
                    stage = "🔀 Tunnel Request"
                elif ev_id == "cowrie.session.closed":
                    dur_val = r.get("duration", "—")
                    desc = f"Session disconnected and closed (duration: {dur_val}s)"
                    stage = "🛑 Session Closed"
                else:
                    desc = str(r.get("message", "—"))
                    stage = "📋 Telemetry Event"

                timeline_records.append({
                    "Timestamp (UTC)": ts_str,
                    "Lifecycle Stage": stage,
                    "Event ID": ev_id,
                    "Forensic Details & Evidence": desc,
                })

            st.dataframe(pd.DataFrame(timeline_records), use_container_width=True, hide_index=True, height=320)
    else:
        st.caption("Enter a Session ID above or select one from the dropdown to view its reconstructed chronological timeline.")

    # ── Methodology & Detection Principles ────────────────────────────────────
    section("Rule-Based Detection & Severity Methodology")
    st.markdown("""
    <div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:18px 22px;font-size:13px;line-height:1.9;color:#c9d1d9;">
        <strong style="color:#58a6ff;">Deterministic Severity Classification:</strong> Severities (Critical, High, Medium, Low) are assigned using deterministic, threshold-escalation multipliers rather than opaque probability scores.<br>
        <strong style="color:#f85149;">Rule A (Repeated Failures):</strong> Escalates from Medium (&ge; threshold) to High (&ge; 2x) to Critical (&ge; 3x) based on per-session failure volume.<br>
        <strong style="color:#f0883e;">Rules B & C (Spraying & Reuse):</strong> Baseline Medium at threshold; escalates to High at &ge; 2x threshold.<br>
        <strong style="color:#3fb950;">Rules D & E (Mixed Auth & Shell Activity):</strong> Classified as Medium by default; verified forensic activity without speculative attribution.<br>
        <strong style="color:#bc8cff;">Analyst Safety:</strong> All displayed credentials remain masked. Raw passwords are never exposed in tables, tooltips, or search parameters.
    </div>
    """, unsafe_allow_html=True)
