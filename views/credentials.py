"""
views/credentials.py — Credential Attacks (Page 4)
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

from utils.ui import demo_banner, section, coming_soon, C, base_layout, AXIS_STYLE, legend_style, OUTCOME_COLORS
from utils.data_loader import is_demo_mode


def render(data: dict):
    creds = data["credentials"]

    st.markdown("## 🔑 Credential Attacks")
    st.markdown(
        '<p style="color:#8b949e;margin-top:-10px;font-size:14px;">'
        "Brute-force and dictionary authentication telemetry — targeted usernames, attempted passwords, and success rates.</p>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    if is_demo_mode():
        demo_banner()

    # ── KPI cards ─────────────────────────────────────────────────────────────
    section("Authentication Summary")
    total   = len(creds)
    success = int((creds["login_success"] == True).sum()) if not creds.empty else 0
    failed  = total - success
    rate    = f"{success / total * 100:.2f}%" if total else "—"

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Login Attempts", f"{total:,}")
    c2.metric("Failed Attempts",      f"{failed:,}")
    c3.metric("Successful Logins",    f"{success:,}")
    c4.metric("Success Rate",         rate)

    if creds.empty:
        st.info("No authentication attempt events found in the current dataset.")
        return

    # ── Top usernames + passwords ─────────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        section("Top Targeted Usernames")
        clean_u = creds["username"].dropna().astype(str)
        empty_u_mask = clean_u.str.strip().eq("")
        valid_usernames = clean_u[~empty_u_mask]
        u_counts = valid_usernames.value_counts().head(12).reset_index()
        u_counts.columns = ["username", "count"]
        u_counts["display_user"] = u_counts["username"].apply(lambda x: f"{x[:26]}..." if len(x) > 28 else x)
        fig1 = px.bar(
            u_counts, x="count", y="display_user", orientation="h",
            color="count",
            color_continuous_scale=[[0, "#5a2e0a"], [1, C["orange"]]],
            custom_data=["username", "count"],
            labels={"display_user": "Username", "count": "Attempts"},
        )
        fig1.update_traces(
            hovertemplate="<b>%{customdata[0]}</b><br>Attempts: %{customdata[1]:,}<extra></extra>"
        )
        fig1.update_layout(
            **base_layout(height=320),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Attempts"),
            yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
        )
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        section("Top Attempted Passwords")
        clean_p = creds["password"].dropna().astype(str)
        empty_pwd_mask = clean_p.str.strip().eq("")
        empty_pwd_count = int(empty_pwd_mask.sum())
        valid_passwords = clean_p[~empty_pwd_mask]
        p_counts = valid_passwords.value_counts().head(12).reset_index()
        p_counts.columns = ["password", "count"]
        p_counts["display_password"] = [f"Password Variant {i+1} [REDACTED]" for i in range(len(p_counts))]
        fig2 = px.bar(
            p_counts, x="count", y="display_password", orientation="h",
            color="count",
            color_continuous_scale=[[0, "#5a1a1a"], [1, C["red"]]],
            custom_data=["display_password", "count"],
            labels={"display_password": "Password", "count": "Attempts"},
        )
        fig2.update_traces(
            hovertemplate="<b>%{customdata[0]}</b><br>Attempts: %{customdata[1]:,}<extra></extra>"
        )
        fig2.update_layout(
            **base_layout(height=320),
            coloraxis_showscale=False,
            xaxis=dict(**AXIS_STYLE, title="Attempts"),
            yaxis=dict(**AXIS_STYLE, type="category", autorange="reversed", title=""),
        )
        st.plotly_chart(fig2, use_container_width=True)
        if empty_pwd_count > 0:
            st.caption(f"ℹ️ Excludes {empty_pwd_count:,} blank/empty password attempts. All attempted password values are redacted for privacy.")

    # ── Failed vs Successful donut ────────────────────────────────────────────
    section("Login Outcome")
    col3, col4 = st.columns([1, 2])

    with col3:
        fig3 = go.Figure(go.Pie(
            labels=["Failed", "Successful"],
            values=[failed, success],
            hole=0.6,
            marker=dict(colors=[OUTCOME_COLORS["Failed"], OUTCOME_COLORS["Successful"]]),
            textinfo="percent",
            textposition="inside",
            hovertemplate="<b>%{label}</b><br>Attempts: %{value:,}<br>Share: %{percent}<extra></extra>",
            textfont=dict(size=12),
        ))
        fig3.update_layout(
            **base_layout(height=230),
            showlegend=True,
            legend=legend_style(orientation="h"),
        )
        st.plotly_chart(fig3, use_container_width=True)

    with col4:
        section("Top Credential Pairs")
        clean_creds = creds.copy()
        clean_creds["u"] = clean_creds["username"].fillna("(empty)").replace("", "(empty)").astype(str)
        clean_creds["p"] = clean_creds["password"].fillna("(empty/blank)").replace("", "(empty/blank)").astype(str)
        cred_table = (
            clean_creds.groupby(["u", "p"])
            .agg(
                attempts=("login_success", "count"),
                successes=("login_success", lambda x: (x == True).sum()),
            )
            .reset_index()
        )
        cred_table["failures"]     = cred_table["attempts"] - cred_table["successes"]
        cred_table["success_rate"] = (
            (cred_table["successes"] / cred_table["attempts"] * 100)
            .round(1).astype(str) + "%"
        )
        cred_table = cred_table.sort_values("attempts", ascending=False).head(20)
        # Redact raw password values in display table while keeping groupings intact
        cred_table["p_display"] = cred_table["p"].apply(lambda x: "(empty/blank)" if x == "(empty/blank)" else "[REDACTED]")
        display_cred_table = cred_table[["u", "p_display", "attempts", "successes", "failures", "success_rate"]]
        display_cred_table.columns = ["Username", "Password", "Attempts", "Successes", "Failures", "Success Rate"]
        st.dataframe(display_cred_table, use_container_width=True, height=230, hide_index=True)

    # ── Recent login log ──────────────────────────────────────────────────────
    section("Recent Authentication Attempts")
    ip_col = "src_ip_identifier" if "src_ip_identifier" in creds.columns else "source_ip"
    c_col = "country_name" if "country_name" in creds.columns else "country"
    display = creds.sort_values("timestamp", ascending=False).head(15).copy()
    display["timestamp"]     = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.%f").str[:-3]
    display["Outcome"]       = display["login_success"].map({True: "✅ Success", False: "❌ Failed"})
    display["Password"]      = display["password"].apply(lambda x: "(empty/blank)" if pd.isna(x) or str(x).strip() == "" else "[REDACTED]")
    
    show_cols = ["timestamp", ip_col, c_col, "username", "Password", "Outcome"]
    renames = {ip_col: "Attacker Identifier", c_col: "Country", "username": "Username"}
    st.dataframe(
        display[[c for c in show_cols if c in display.columns]].rename(columns=renames),
        use_container_width=True,
        height=260,
        hide_index=True,
    )

    # ── Heatmap placeholder ───────────────────────────────────────────────────
    section("Username × Password Heatmap")
    coming_soon("Pairwise credential matrix — top user-password co-occurrence clustering (Stage 3)")
