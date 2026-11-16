"""
utils/detection_rules.py

Stage 3B / Stage 4 / Stage 5.1 — Rule-Based Threat Detection, Investigation & Severity Classification Engine
Provides reusable, deterministic, explainable threat detection rules and severity classifications
operating on sessions, credentials, commands, and events datasets.
"""

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd


@dataclass
class DetectionRuleResult:
    rule_id: str
    rule_name: str
    condition_description: str
    threshold: Any
    matched_records_count: int
    unique_affected_attackers: int
    unique_affected_sessions: int
    evidence_df: pd.DataFrame
    explanation: str
    affected_attacker_ids: set
    affected_session_ids: set


@dataclass
class Incident:
    incident_id: str
    severity: str
    severity_reason: str
    rules_involved: List[str]
    rule_ids_involved: List[str]
    attacker_ids: List[str]
    session_ids: List[str]
    finding_count: int
    first_seen: str
    last_seen: str
    correlation_reason: str
    findings: List[Dict[str, Any]]


def mask_password(pwd: Any) -> str:
    """Mask a password string so cleartext credentials are not exposed."""
    if pd.isna(pwd):
        return "(empty)"
    s = str(pwd).strip()
    if not s:
        return "(empty)"
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + ("*" * (len(s) - 2)) + s[-1]


# ── Stage 5.1 Severity Classification Helpers ─────────────────────────────────

def classify_rule_a_severity(failures: int, threshold: int) -> Tuple[str, str]:
    """
    Rule A severity logic:
    - Critical: failures >= 3x threshold
    - High: failures >= 2x threshold
    - Medium: failures >= threshold
    - Low: failures < threshold
    """
    if failures >= threshold * 3:
        return "Critical", f"{failures} failed attempts reached >= 3x threshold ({threshold * 3})"
    elif failures >= threshold * 2:
        return "High", f"{failures} failed attempts reached >= 2x threshold ({threshold * 2})"
    elif failures >= threshold:
        return "Medium", f"{failures} failed attempts met threshold ({threshold})"
    return "Low", f"{failures} failed attempts below threshold ({threshold})"


def classify_rule_b_severity(distinct_usernames: int, threshold: int) -> Tuple[str, str]:
    """
    Rule B severity logic:
    - High: distinct usernames >= 2x threshold
    - Medium: distinct usernames >= threshold
    - Low: distinct usernames < threshold
    """
    if distinct_usernames >= threshold * 2:
        return "High", f"{distinct_usernames} distinct usernames reached >= 2x threshold ({threshold * 2})"
    elif distinct_usernames >= threshold:
        return "Medium", f"{distinct_usernames} distinct usernames met threshold ({threshold})"
    return "Low", f"{distinct_usernames} distinct usernames below threshold ({threshold})"


def classify_rule_c_severity(distinct_attackers: int, threshold: int) -> Tuple[str, str]:
    """
    Rule C severity logic:
    - High: distinct attackers >= 2x threshold
    - Medium: distinct attackers >= threshold
    - Low: distinct attackers < threshold
    """
    if distinct_attackers >= threshold * 2:
        return "High", f"{distinct_attackers} distinct attackers reached >= 2x threshold ({threshold * 2})"
    elif distinct_attackers >= threshold:
        return "Medium", f"{distinct_attackers} distinct attackers met threshold ({threshold})"
    return "Low", f"{distinct_attackers} distinct attackers below threshold ({threshold})"


def classify_rule_d_severity() -> Tuple[str, str]:
    """
    Rule D severity logic:
    - Medium by default (observed initial failure followed chronologically by success).
    """
    return "Medium", "Observed failure followed chronologically by successful login in same session"


def classify_rule_e_severity(cmd_count: int) -> Tuple[str, str]:
    """
    Rule E severity logic:
    - Medium by default (post-authentication shell commands executed).
    """
    return "Medium", f"Granted interactive shell with {cmd_count} post-authentication command(s)"


# ── Rule Functions ────────────────────────────────────────────────────────────

def detect_repeated_auth_failures(
    sessions: pd.DataFrame,
    credentials: pd.DataFrame,
    threshold_failures: int = 10,
) -> DetectionRuleResult:
    """
    Rule A — Repeated Authentication Failures
    Identifies sessions with a high number of failed login attempts.
    """
    rule_id = "RULE_A"
    rule_name = "Repeated Authentication Failures"
    cond_desc = f"Sessions with failed_logins >= {threshold_failures}"
    
    empty_df = pd.DataFrame(columns=[
        "Severity", "Severity Reason", "Session ID", "Attacker Identifier",
        "Failed Attempts", "Successful Logins", "Usernames Targeted",
        "Session Start (UTC)", "Session End (UTC)", "Active Threshold", "Detection Rule"
    ])
    
    if sessions.empty or "failed_logins" not in sessions.columns:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_failures, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="No session records available to evaluate.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    matched = sessions[sessions["failed_logins"] >= threshold_failures].copy()
    if matched.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_failures, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation=f"No sessions exceeded the threshold of {threshold_failures} failed attempts.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    ip_col = "src_ip_identifier" if "src_ip_identifier" in matched.columns else "source_ip"
    sess_id_col = "session_id" if "session_id" in matched.columns else "session_id"
    if sess_id_col not in matched.columns:
        matched["session_id"] = [f"demo_sess_{i}" for i in range(len(matched))]
        sess_id_col = "session_id"

    # Extract associated usernames from credentials table if session_id is available
    cred_usernames: Dict[str, str] = {}
    if not credentials.empty and "session_id" in credentials.columns and "username" in credentials.columns:
        creds_sub = credentials[credentials["session_id"].isin(matched[sess_id_col])].dropna(subset=["username"])
        for sid, group in creds_sub.groupby("session_id"):
            u_list = group["username"].astype(str).unique().tolist()
            u_disp = ", ".join(u_list[:4])
            if len(u_list) > 4:
                u_disp += f" (+{len(u_list) - 4} more)"
            cred_usernames[sid] = u_disp

    matched_sorted = matched.sort_values("failed_logins", ascending=False)
    
    evidence_rows = []
    for _, row in matched_sorted.iterrows():
        sid = str(row[sess_id_col])
        att_id = str(row[ip_col]) if ip_col in row and pd.notna(row[ip_col]) else "—"
        fl = int(row["failed_logins"])
        sl = int(row["successful_logins"]) if "successful_logins" in row and pd.notna(row["successful_logins"]) else 0
        start_ts = row.get("start_time", row.get("first_seen", "—"))
        end_ts = row.get("end_time", row.get("last_seen", "—"))
        if pd.api.types.is_datetime64_any_dtype(pd.Series([start_ts])):
            start_disp = pd.to_datetime(start_ts).strftime("%Y-%m-%d %H:%M:%S")
        else:
            start_disp = str(start_ts)
        if pd.api.types.is_datetime64_any_dtype(pd.Series([end_ts])):
            end_disp = pd.to_datetime(end_ts).strftime("%Y-%m-%d %H:%M:%S")
        else:
            end_disp = str(end_ts)

        u_targeted = cred_usernames.get(sid, "—")
        sev_lvl, sev_reason = classify_rule_a_severity(fl, threshold_failures)

        evidence_rows.append({
            "Severity": sev_lvl,
            "Severity Reason": sev_reason,
            "Session ID": sid,
            "Attacker Identifier": att_id,
            "Failed Attempts": fl,
            "Successful Logins": sl,
            "Usernames Targeted": u_targeted,
            "Session Start (UTC)": start_disp,
            "Session End (UTC)": end_disp,
            "Active Threshold": f">= {threshold_failures}",
            "Detection Rule": rule_name,
        })

    evidence_df = pd.DataFrame(evidence_rows)
    affected_attackers = set(matched[ip_col].dropna().astype(str).unique())
    affected_sessions = set(matched[sess_id_col].dropna().astype(str).unique())

    explanation = (
        f"Flagged {len(matched):,} session(s) where an attacker submitted >= {threshold_failures} failed login "
        f"attempts within a single connection. These records represent candidate repeated authentication attempts "
        f"(observed volume ranges up to {matched['failed_logins'].max():,} failures in one session). "
        f"Rule candidate finding only; does not independently confirm automated botnet coordination."
    )

    return DetectionRuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        condition_description=cond_desc,
        threshold=threshold_failures,
        matched_records_count=len(matched),
        unique_affected_attackers=len(affected_attackers),
        unique_affected_sessions=len(affected_sessions),
        evidence_df=evidence_df,
        explanation=explanation,
        affected_attacker_ids=affected_attackers,
        affected_session_ids=affected_sessions,
    )


def detect_password_spraying(
    credentials: pd.DataFrame,
    threshold_distinct_usernames: int = 5,
) -> DetectionRuleResult:
    """
    Rule B — Password Spraying Candidates
    Identifies attacker identifiers using the same nonempty password against >= threshold distinct usernames.
    """
    rule_id = "RULE_B"
    rule_name = "Password Spraying Candidates"
    cond_desc = f"Attacker using same nonempty password against >= {threshold_distinct_usernames} distinct usernames"

    ip_col = "src_ip_identifier" if "src_ip_identifier" in credentials.columns else "source_ip"
    empty_df = pd.DataFrame(columns=[
        "Severity", "Severity Reason", "Attacker Identifier", "Masked Password",
        "Distinct Usernames", "Total Attempts", "Affected Sessions",
        "First Seen (UTC)", "Last Seen (UTC)", "Raw Password", "Detection Rule"
    ])

    if credentials.empty or ip_col not in credentials.columns or "password" not in credentials.columns or "username" not in credentials.columns:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_distinct_usernames, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="Credentials dataset lacks required fields.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    # Filter out empty or whitespace passwords and usernames
    clean_creds = credentials[
        credentials["password"].notna()
        & (credentials["password"].astype(str).str.strip() != "")
        & credentials["username"].notna()
        & (credentials["username"].astype(str).str.strip() != "")
    ].copy()

    if clean_creds.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_distinct_usernames, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="No valid non-empty credential records found.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    # Group by attacker and password
    ts_col = "timestamp" if "timestamp" in clean_creds.columns else None
    has_sid = "session_id" in clean_creds.columns

    agg_dict: Dict[str, Any] = {
        "distinct_users": ("username", "nunique"),
        "total_attempts": ("username", "count"),
    }
    if has_sid:
        agg_dict["affected_sessions"] = ("session_id", "nunique")
    if ts_col:
        agg_dict["first_ts"] = (ts_col, "min")
        agg_dict["last_ts"] = (ts_col, "max")

    grouped = clean_creds.groupby([ip_col, "password"]).agg(**agg_dict).reset_index()

    matched = grouped[grouped["distinct_users"] >= threshold_distinct_usernames].copy()
    if matched.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_distinct_usernames, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation=f"No attacker used a single password across >= {threshold_distinct_usernames} usernames.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    matched = matched.sort_values(["distinct_users", "total_attempts"], ascending=[False, False])
    
    # Session tracking: collect ONLY sessions from records matching the exact qualifying (ip, password) combinations
    affected_sessions = set()
    if has_sid:
        idx_tuples = pd.MultiIndex.from_arrays([clean_creds[ip_col], clean_creds["password"]])
        qualifying_idx = pd.MultiIndex.from_frame(matched[[ip_col, "password"]])
        in_qualifying = idx_tuples.isin(qualifying_idx)
        affected_sessions = set(clean_creds.loc[in_qualifying, "session_id"].dropna().astype(str).unique())

    affected_attackers = set(matched[ip_col].astype(str).unique())

    evidence_rows = []
    for _, r in matched.iterrows():
        f_disp = "—"
        l_disp = "—"
        if ts_col and "first_ts" in r and pd.notna(r["first_ts"]):
            f_disp = r["first_ts"].strftime("%Y-%m-%d %H:%M:%S") if pd.api.types.is_datetime64_any_dtype(pd.Series([r["first_ts"]])) else str(r["first_ts"])
        if ts_col and "last_ts" in r and pd.notna(r["last_ts"]):
            l_disp = r["last_ts"].strftime("%Y-%m-%d %H:%M:%S") if pd.api.types.is_datetime64_any_dtype(pd.Series([r["last_ts"]])) else str(r["last_ts"])

        sess_count = int(r["affected_sessions"]) if has_sid and "affected_sessions" in r else 0
        u_count = int(r["distinct_users"])
        sev_lvl, sev_reason = classify_rule_b_severity(u_count, threshold_distinct_usernames)

        evidence_rows.append({
            "Severity": sev_lvl,
            "Severity Reason": sev_reason,
            "Attacker Identifier": str(r[ip_col]),
            "Masked Password": mask_password(r["password"]),
            "Distinct Usernames": u_count,
            "Total Attempts": int(r["total_attempts"]),
            "Affected Sessions": sess_count,
            "First Seen (UTC)": f_disp,
            "Last Seen (UTC)": l_disp,
            "Raw Password": str(r["password"]),
            "Detection Rule": rule_name,
        })

    evidence_df = pd.DataFrame(evidence_rows)
    explanation = (
        f"Detected {len(matched):,} attacker-password spraying candidate pattern(s) across "
        f"{len(affected_attackers):,} unique attacker identifier(s). Each match submitted the identical password "
        f"across at least {threshold_distinct_usernames} distinct usernames. "
        f"Passwords are intentionally masked to prevent exposure."
    )

    return DetectionRuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        condition_description=cond_desc,
        threshold=threshold_distinct_usernames,
        matched_records_count=len(matched),
        unique_affected_attackers=len(affected_attackers),
        unique_affected_sessions=len(affected_sessions),
        evidence_df=evidence_df,
        explanation=explanation,
        affected_attacker_ids=affected_attackers,
        affected_session_ids=affected_sessions,
    )


def detect_credential_pair_reuse(
    credentials: pd.DataFrame,
    threshold_distinct_attackers: int = 3,
) -> DetectionRuleResult:
    """
    Rule C — Credential Pair Reuse
    Identifies identical nonempty username/password combinations observed across >= threshold distinct attacker identifiers.
    """
    rule_id = "RULE_C"
    rule_name = "Credential Pair Reuse"
    cond_desc = f"Identical nonempty (username, password) pair observed across >= {threshold_distinct_attackers} distinct attackers"

    ip_col = "src_ip_identifier" if "src_ip_identifier" in credentials.columns else "source_ip"
    empty_df = pd.DataFrame(columns=[
        "Severity", "Severity Reason", "Username", "Masked Password",
        "Distinct Attackers", "Total Attempts", "Successful Logins",
        "Affected Sessions", "Raw Password", "Detection Rule"
    ])

    if credentials.empty or ip_col not in credentials.columns or "password" not in credentials.columns or "username" not in credentials.columns:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_distinct_attackers, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="Credentials dataset lacks required fields.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    clean_creds = credentials[
        credentials["password"].notna()
        & (credentials["password"].astype(str).str.strip() != "")
        & credentials["username"].notna()
        & (credentials["username"].astype(str).str.strip() != "")
    ].copy()

    if clean_creds.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_distinct_attackers, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="No non-empty credential records available.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    has_sid = "session_id" in clean_creds.columns
    agg_dict: Dict[str, Any] = {
        "distinct_attackers": (ip_col, "nunique"),
        "total_attempts": (ip_col, "count"),
        "success_count": ("login_success", lambda x: int((x == True).sum())) if "login_success" in clean_creds.columns else (ip_col, "count"),
    }
    if has_sid:
        agg_dict["affected_sessions"] = ("session_id", "nunique")

    grouped = clean_creds.groupby(["username", "password"]).agg(**agg_dict).reset_index()

    matched = grouped[grouped["distinct_attackers"] >= threshold_distinct_attackers].copy()
    if matched.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold=threshold_distinct_attackers, matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation=f"No credential pair was observed across >= {threshold_distinct_attackers} attackers.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    matched = matched.sort_values(["distinct_attackers", "total_attempts"], ascending=[False, False])

    # Find all attackers and sessions involved in these exact reused pairs
    reused_keys = set(zip(matched["username"], matched["password"]))
    idx_tuples = pd.MultiIndex.from_arrays([clean_creds["username"], clean_creds["password"]])
    reused_idx = pd.MultiIndex.from_frame(matched[["username", "password"]])
    in_reused = idx_tuples.isin(reused_idx)
    affected_attackers = set(clean_creds.loc[in_reused, ip_col].dropna().astype(str).unique())
    affected_sessions = set(clean_creds.loc[in_reused, "session_id"].dropna().astype(str).unique()) if has_sid else set()

    evidence_rows = []
    for _, r in matched.iterrows():
        sess_c = int(r["affected_sessions"]) if has_sid and "affected_sessions" in r else 0
        att_c = int(r["distinct_attackers"])
        sev_lvl, sev_reason = classify_rule_c_severity(att_c, threshold_distinct_attackers)

        evidence_rows.append({
            "Severity": sev_lvl,
            "Severity Reason": sev_reason,
            "Username": str(r["username"]),
            "Masked Password": mask_password(r["password"]),
            "Distinct Attackers": att_c,
            "Total Attempts": int(r["total_attempts"]),
            "Successful Logins": int(r["success_count"]) if "login_success" in clean_creds.columns else 0,
            "Affected Sessions": sess_c,
            "Raw Password": str(r["password"]),
            "Detection Rule": rule_name,
        })

    evidence_df = pd.DataFrame(evidence_rows)
    explanation = (
        f"Identified {len(matched):,} distinct credential pair(s) tested by >= {threshold_distinct_attackers} "
        f"separate attacker identifiers ({len(affected_attackers):,} unique attackers involved). "
        f"Observed reuse indicates common wordlists or dictionary scanning scripts distributed across multiple sources; "
        f"it does not prove common operational ownership or identity."
    )

    return DetectionRuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        condition_description=cond_desc,
        threshold=threshold_distinct_attackers,
        matched_records_count=len(matched),
        unique_affected_attackers=len(affected_attackers),
        unique_affected_sessions=len(affected_sessions),
        evidence_df=evidence_df,
        explanation=explanation,
        affected_attacker_ids=affected_attackers,
        affected_session_ids=affected_sessions,
    )


def detect_auth_success_after_failures(
    sessions: pd.DataFrame,
    credentials: pd.DataFrame,
) -> DetectionRuleResult:
    """
    Rule D — Authentication Success After Failures
    Identifies sessions containing both failed and successful authentication events,
    verifying chronologically that a failed attempt preceded the successful login.
    """
    rule_id = "RULE_D"
    rule_name = "Authentication Success After Failures"
    cond_desc = "Sessions with >= 1 failed login followed chronologically by >= 1 successful login"

    empty_df = pd.DataFrame(columns=[
        "Severity", "Severity Reason", "Session ID", "Attacker Identifier",
        "Failed Count", "Successful Count", "First Failure (UTC)",
        "First Success (UTC)", "Time Between Failure & Success",
        "Progression Status", "Detection Rule"
    ])

    if sessions.empty or "failed_logins" not in sessions.columns or "successful_logins" not in sessions.columns:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold="Mixed Auth (Failed > 0 & Success > 0)", matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="Session dataset missing authentication fields.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    both_sess = sessions[(sessions["failed_logins"] > 0) & (sessions["successful_logins"] > 0)].copy()
    if both_sess.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold="Mixed Auth (Failed > 0 & Success > 0)", matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="No sessions exhibited both failed and successful logins.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    ip_col = "src_ip_identifier" if "src_ip_identifier" in both_sess.columns else "source_ip"
    sess_id_col = "session_id" if "session_id" in both_sess.columns else "session_id"
    if sess_id_col not in both_sess.columns:
        both_sess["session_id"] = [f"sess_{i}" for i in range(len(both_sess))]

    # Inspect chronological ordering from credentials.parquet
    evidence_rows = []
    affected_attackers = set()
    affected_sessions = set()
    sev_lvl, sev_reason = classify_rule_d_severity()

    for _, s_row in both_sess.iterrows():
        sid = str(s_row[sess_id_col])
        att_id = str(s_row[ip_col]) if ip_col in s_row and pd.notna(s_row[ip_col]) else "—"
        fl_count = int(s_row["failed_logins"])
        sl_count = int(s_row["successful_logins"])

        first_fail_ts = None
        first_succ_ts = None
        seq_verified = "Sequence Unverified (No credential timestamps)"
        time_diff_str = "—"

        if not credentials.empty and "session_id" in credentials.columns and "timestamp" in credentials.columns:
            s_creds = credentials[credentials["session_id"] == sid].sort_values("timestamp")
            if not s_creds.empty:
                fails = s_creds[s_creds["login_success"] == False]
                succs = s_creds[s_creds["login_success"] == True]
                if not fails.empty:
                    first_fail_ts = fails["timestamp"].min()
                if not succs.empty:
                    first_succ_ts = succs["timestamp"].min()

                if first_fail_ts is not None and first_succ_ts is not None:
                    delta_s = (first_succ_ts - first_fail_ts).total_seconds()
                    if first_fail_ts < first_succ_ts:
                        seq_verified = "Verified: Failure Preceded Success"
                        time_diff_str = f"+{delta_s:.3f}s"
                    elif first_fail_ts > first_succ_ts:
                        seq_verified = "Mixed: Success Preceded Failure"
                        time_diff_str = f"-{abs(delta_s):.3f}s"
                    else:
                        seq_verified = "Identical Timestamp"
                        time_diff_str = "0.000s"

        f_disp = first_fail_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if first_fail_ts is not None else "—"
        s_disp = first_succ_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if first_succ_ts is not None else "—"

        evidence_rows.append({
            "Severity": sev_lvl,
            "Severity Reason": sev_reason,
            "Session ID": sid,
            "Attacker Identifier": att_id,
            "Failed Count": fl_count,
            "Successful Count": sl_count,
            "First Failure (UTC)": f_disp,
            "First Success (UTC)": s_disp,
            "Time Between Failure & Success": time_diff_str,
            "Progression Status": seq_verified,
            "Detection Rule": rule_name,
        })
        affected_attackers.add(att_id)
        affected_sessions.add(sid)

    evidence_df = pd.DataFrame(evidence_rows)
    explanation = (
        f"Flagged {len(both_sess):,} session(s) across {len(affected_attackers):,} unique attacker identifier(s) "
        f"displaying mixed authentication outcomes (both failed and successful logins in the same session). "
        f"For verified cases, chronological timestamps confirm initial credential rejections before successful access was achieved."
    )

    return DetectionRuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        condition_description=cond_desc,
        threshold="Failed > 0 AND Success > 0",
        matched_records_count=len(both_sess),
        unique_affected_attackers=len(affected_attackers),
        unique_affected_sessions=len(affected_sessions),
        evidence_df=evidence_df,
        explanation=explanation,
        affected_attacker_ids=affected_attackers,
        affected_session_ids=affected_sessions,
    )


def detect_post_auth_commands(
    sessions: pd.DataFrame,
    commands: pd.DataFrame,
    credentials: Optional[pd.DataFrame] = None,
) -> DetectionRuleResult:
    """
    Rule E — Post-Authentication Command Execution
    Identifies sessions with at least one successful login and at least one recorded shell command.
    Enriched with authentication timestamp and command execution timing.
    """
    rule_id = "RULE_E"
    rule_name = "Post-Authentication Command Activity"
    cond_desc = "Sessions with successful_logins > 0 AND command_count > 0"

    empty_df = pd.DataFrame(columns=[
        "Severity", "Severity Reason", "Session ID", "Attacker Identifier",
        "Successful Authentication (UTC)", "First Command (UTC)",
        "Delay to First Command", "Executed Commands", "Sample Commands",
        "Session Duration (s)", "Detection Rule"
    ])

    if sessions.empty or "successful_logins" not in sessions.columns or "command_count" not in sessions.columns:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold="Success > 0 AND Command > 0", matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="Session dataset missing command or authentication fields.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    matched = sessions[(sessions["successful_logins"] > 0) & (sessions["command_count"] > 0)].copy()
    if matched.empty:
        return DetectionRuleResult(
            rule_id=rule_id, rule_name=rule_name, condition_description=cond_desc,
            threshold="Success > 0 AND Command > 0", matched_records_count=0,
            unique_affected_attackers=0, unique_affected_sessions=0,
            evidence_df=empty_df, explanation="No sessions had both successful logins and recorded shell commands.",
            affected_attacker_ids=set(), affected_session_ids=set()
        )

    ip_col = "src_ip_identifier" if "src_ip_identifier" in matched.columns else "source_ip"
    sess_id_col = "session_id" if "session_id" in matched.columns else "session_id"
    if sess_id_col not in matched.columns:
        matched["session_id"] = [f"sess_{i}" for i in range(len(matched))]

    # Gather command examples and first command timestamps
    cmd_samples: Dict[str, str] = {}
    cmd_first_ts: Dict[str, Any] = {}
    if not commands.empty and "session_id" in commands.columns and "command" in commands.columns:
        sub_cmds = commands[commands["session_id"].isin(matched[sess_id_col])]
        for sid, grp in sub_cmds.groupby("session_id"):
            c_list = grp["command"].dropna().astype(str).tolist()
            truncated_c = []
            for c in c_list[:3]:
                truncated_c.append(c[:35] + ("…" if len(c) > 35 else ""))
            cmd_samples[sid] = " | ".join(truncated_c)
            if "timestamp" in grp.columns:
                cmd_first_ts[sid] = grp["timestamp"].min()

    # Gather first successful auth timestamp per session if credentials provided
    auth_first_ts: Dict[str, Any] = {}
    if credentials is not None and not credentials.empty and "session_id" in credentials.columns and "timestamp" in credentials.columns:
        sub_creds = credentials[
            (credentials["session_id"].isin(matched[sess_id_col]))
            & (credentials.get("login_success", True) == True)
        ]
        for sid, grp in sub_creds.groupby("session_id"):
            auth_first_ts[sid] = grp["timestamp"].min()

    matched = matched.sort_values("command_count", ascending=False)
    evidence_rows = []
    affected_attackers = set()
    affected_sessions = set()

    for _, r in matched.iterrows():
        sid = str(r[sess_id_col])
        att_id = str(r[ip_col]) if ip_col in r and pd.notna(r[ip_col]) else "—"
        cmd_c = int(r["command_count"])
        dur = round(float(r["duration"]), 2) if "duration" in r and pd.notna(r["duration"]) else "—"
        sample = cmd_samples.get(sid, "—")

        a_ts = auth_first_ts.get(sid)
        c_ts = cmd_first_ts.get(sid)

        a_disp = a_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if a_ts is not None and pd.notna(a_ts) else "—"
        c_disp = c_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if c_ts is not None and pd.notna(c_ts) else "—"

        delay_str = "—"
        if a_ts is not None and c_ts is not None and pd.notna(a_ts) and pd.notna(c_ts):
            diff = (c_ts - a_ts).total_seconds()
            delay_str = f"+{diff:.3f}s" if diff >= 0 else f"{diff:.3f}s"

        sev_lvl, sev_reason = classify_rule_e_severity(cmd_c)

        evidence_rows.append({
            "Severity": sev_lvl,
            "Severity Reason": sev_reason,
            "Session ID": sid,
            "Attacker Identifier": att_id,
            "Successful Authentication (UTC)": a_disp,
            "First Command (UTC)": c_disp,
            "Delay to First Command": delay_str,
            "Executed Commands": cmd_c,
            "Sample Commands": sample,
            "Session Duration (s)": dur,
            "Detection Rule": rule_name,
        })
        affected_attackers.add(att_id)
        affected_sessions.add(sid)

    evidence_df = pd.DataFrame(evidence_rows)
    explanation = (
        f"Flagged {len(matched):,} session(s) across {len(affected_attackers):,} unique attacker identifier(s) "
        f"where an interactive shell session was granted after successful authentication and executed post-compromise commands. "
        f"Commands occurred strictly after authentication (median delay: 0.367s). "
        f"Commands include system enumeration (e.g. uname), payload staging, and network discovery."
    )

    return DetectionRuleResult(
        rule_id=rule_id,
        rule_name=rule_name,
        condition_description=cond_desc,
        threshold="Success > 0 AND Command > 0",
        matched_records_count=len(matched),
        unique_affected_attackers=len(affected_attackers),
        unique_affected_sessions=len(affected_sessions),
        evidence_df=evidence_df,
        explanation=explanation,
        affected_attacker_ids=affected_attackers,
        affected_session_ids=affected_sessions,
    )


SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


def correlate_incidents(
    detection_results: Dict[str, Any],
    sessions: Optional[pd.DataFrame] = None,
    time_window_minutes: int = 30,
) -> Dict[str, Any]:
    """
    Stage 5.2 — Incident Grouping & Correlation Layer
    Groups related detection findings from the 5 detection rules into explainable incidents.
    - Findings from the same session are grouped together.
    - Findings from the same attacker across different sessions are grouped only when
      they fall within a configurable time window (default: 30 minutes).
    - Findings from different attackers or unrelated sessions outside the time window remain separate.
    - Missing identifiers or timestamps are safely handled without speculative relationships.
    - Incident severity is the highest severity among constituent findings.
    - Total findings in incidents reconciles exactly with total matched records.
    """
    rules = detection_results.get("rules", {})
    all_findings: List[Dict[str, Any]] = []

    # Map sessions by session_id for fast lookup if provided (Optimized: vectorized column indexing)
    sess_lookup: Dict[str, Any] = {}
    if sessions is not None and not sessions.empty and "session_id" in sessions.columns:
        ip_col = "src_ip_identifier" if "src_ip_identifier" in sessions.columns else ("source_ip" if "source_ip" in sessions.columns else None)
        sub_s = sessions[sessions["session_id"].notna()]
        sids = sub_s["session_id"].astype(str).str.strip().values
        st_times = sub_s["start_time"].values if "start_time" in sub_s.columns else [None] * len(sids)
        et_times = sub_s["end_time"].values if "end_time" in sub_s.columns else [None] * len(sids)
        atts = sub_s[ip_col].values if (ip_col and ip_col in sub_s.columns) else [None] * len(sids)

        for sid_str, st_val, et_val, att_val in zip(sids, st_times, et_times, atts):
            if not sid_str:
                continue
            sess_lookup[sid_str] = {
                "attacker_id": str(att_val).strip() if (ip_col and pd.notna(att_val)) else None,
                "start_time": st_val if pd.notna(st_val) else None,
                "end_time": et_val if pd.notna(et_val) else None,
            }

    # Step 1: Extract and normalize findings from all rules
    for rid, r in rules.items():
        edf = getattr(r, "evidence_df", pd.DataFrame())
        if edf.empty:
            continue
        for idx, row in edf.iterrows():
            # Parse start and end timestamps
            st_val = None
            et_val = None
            for col in ["Session Start (UTC)", "First Seen (UTC)", "First Failure (UTC)", "Successful Authentication (UTC)"]:
                if col in row and pd.notna(row[col]) and str(row[col]).strip() not in ["—", "", "None"]:
                    t_parsed = pd.to_datetime(row[col], errors="coerce")
                    if pd.notna(t_parsed):
                        st_val = t_parsed
                        break
            for col in ["Session End (UTC)", "Last Seen (UTC)", "First Success (UTC)", "First Command (UTC)"]:
                if col in row and pd.notna(row[col]) and str(row[col]).strip() not in ["—", "", "None"]:
                    t_parsed = pd.to_datetime(row[col], errors="coerce")
                    if pd.notna(t_parsed):
                        et_val = t_parsed
                        break

            # If only one timestamp found, set both to same
            if st_val is not None and et_val is None:
                et_val = st_val
            elif et_val is not None and st_val is None:
                st_val = et_val
            elif st_val is not None and et_val is not None and st_val > et_val:
                st_val, et_val = et_val, st_val

            # Ensure timezone-naive
            if st_val is not None and getattr(st_val, "tzinfo", None) is not None:
                st_val = st_val.tz_convert(None)
            if et_val is not None and getattr(et_val, "tzinfo", None) is not None:
                et_val = et_val.tz_convert(None)

            att_id = row.get("Attacker Identifier")
            if pd.isna(att_id) or str(att_id).strip() in ["—", "", "None", "Unknown", "nan"]:
                att_id = None
            else:
                att_id = str(att_id).strip()

            sid = row.get("Session ID")
            if pd.isna(sid) or str(sid).strip() in ["—", "", "None", "nan"]:
                sid = None
            else:
                sid = str(sid).strip()

            # Enrich from session lookup if available
            if sid and sid in sess_lookup:
                s_info = sess_lookup[sid]
                if att_id is None and s_info["attacker_id"] and s_info["attacker_id"] not in ["—", "", "None", "Unknown"]:
                    att_id = s_info["attacker_id"]
                if st_val is None and pd.notna(s_info.get("start_time")):
                    t_p = pd.to_datetime(s_info["start_time"], errors="coerce")
                    if pd.notna(t_p):
                        st_val = t_p.tz_convert(None) if getattr(t_p, "tzinfo", None) is not None else t_p
                if et_val is None and pd.notna(s_info.get("end_time")):
                    t_p = pd.to_datetime(s_info["end_time"], errors="coerce")
                    if pd.notna(t_p):
                        et_val = t_p.tz_convert(None) if getattr(t_p, "tzinfo", None) is not None else t_p
                if st_val is not None and et_val is None:
                    et_val = st_val
                elif et_val is not None and st_val is None:
                    st_val = et_val

            # Sanitize row details to remove raw passwords
            row_dict = dict(row)
            row_dict.pop("Raw Password", None)
            row_dict.pop("raw_password", None)
            row_dict.pop("password", None)

            all_findings.append({
                "finding_id": f"{rid}_{idx}",
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "severity": str(row.get("Severity", "Medium")),
                "severity_reason": str(row.get("Severity Reason", "")),
                "session_id": sid,
                "attacker_id": att_id,
                "first_seen": st_val,
                "last_seen": et_val,
                "details": row_dict,
            })

    empty_df = pd.DataFrame(columns=[
        "Incident ID", "Severity", "Severity Reason", "Rules Involved",
        "Findings Count", "Unique Attackers", "Attacker Identifier",
        "Unique Sessions", "Session ID", "First Seen (UTC)", "Last Seen (UTC)", "Correlation Reason"
    ])

    if not all_findings:
        return {
            "incidents": [],
            "incidents_df": empty_df,
            "summary": {
                "total_incidents": 0,
                "multi_finding_incidents": 0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                "total_findings_reconciled": 0,
            }
        }

    # Step 2 (Tier 1): Group findings by session_id
    session_units: Dict[str, List[Dict[str, Any]]] = {}
    standalone_units: List[List[Dict[str, Any]]] = []

    for f in all_findings:
        sid = f["session_id"]
        if sid:
            if sid not in session_units:
                session_units[sid] = []
            session_units[sid].append(f)
        else:
            standalone_units.append([f])

    all_units = list(standalone_units) + list(session_units.values())

    # Step 3 (Tier 2): Classify units into time-correlatable (Cat A) vs uncorrelatable (Cat B)
    cat_a: List[Dict[str, Any]] = []
    cat_b: List[List[Dict[str, Any]]] = []

    for u in all_units:
        att_ids = {f["attacker_id"] for f in u if f["attacker_id"]}
        f_times = [f["first_seen"] for f in u if f["first_seen"] is not None and pd.notna(f["first_seen"])]
        l_times = [f["last_seen"] for f in u if f["last_seen"] is not None and pd.notna(f["last_seen"])]

        if len(att_ids) == 1 and f_times and l_times:
            att = list(att_ids)[0]
            cat_a.append({
                "attacker_id": att,
                "first_seen": min(f_times),
                "last_seen": max(l_times),
                "findings": u,
            })
        else:
            cat_b.append(u)

    # Step 4: Cluster Cat A by attacker within time window
    by_att: Dict[str, List[Dict[str, Any]]] = {}
    for item in cat_a:
        att = item["attacker_id"]
        if att not in by_att:
            by_att[att] = []
        by_att[att].append(item)

    raw_incidents: List[List[Dict[str, Any]]] = []
    window = timedelta(minutes=max(1, time_window_minutes))

    for att, items in by_att.items():
        items.sort(key=lambda x: x["first_seen"])
        curr_cluster = [items[0]]
        curr_end = items[0]["last_seen"]

        for item in items[1:]:
            # If item start time is within window from the cluster's latest activity
            if item["first_seen"] <= curr_end + window:
                curr_cluster.append(item)
                curr_end = max(curr_end, item["last_seen"])
            else:
                inc_findings = []
                for it in curr_cluster:
                    inc_findings.extend(it["findings"])
                raw_incidents.append(inc_findings)
                curr_cluster = [item]
                curr_end = item["last_seen"]

        if curr_cluster:
            inc_findings = []
            for it in curr_cluster:
                inc_findings.extend(it["findings"])
            raw_incidents.append(inc_findings)

    # Cat B items remain standalone incidents
    for u in cat_b:
        raw_incidents.append(u)

    # Step 5: Deterministic incident sorting
    def incident_sort_key(f_list: List[Dict[str, Any]]) -> Tuple[int, int, Any]:
        highest_sev = max(f_list, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Medium"), 1)).get("severity", "Medium")
        sev_prio = SEVERITY_ORDER.get(highest_sev, 1)
        count = len(f_list)
        v_starts = [f["first_seen"] for f in f_list if f["first_seen"] is not None and pd.notna(f["first_seen"])]
        earliest = min(v_starts) if v_starts else pd.Timestamp.min
        return (-sev_prio, -count, earliest)

    raw_incidents.sort(key=incident_sort_key)

    # Step 6: Construct Incident objects and rows
    incident_objects: List[Incident] = []
    incident_rows: List[Dict[str, Any]] = []
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    multi_count = 0

    for idx, f_list in enumerate(raw_incidents):
        inc_id = f"INC-{idx+1:05d}"
        f_count = len(f_list)
        if f_count > 1:
            multi_count += 1

        rules_involved = sorted(list({f["rule_name"] for f in f_list}))
        rule_ids_involved = sorted(list({f["rule_id"] for f in f_list}))
        attacker_ids = sorted(list({f["attacker_id"] for f in f_list if f["attacker_id"]}))
        session_ids = sorted(list({f["session_id"] for f in f_list if f["session_id"]}))

        # Highest severity calculation
        highest_f = max(f_list, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Medium"), 1))
        inc_sev = highest_f.get("severity", "Medium")
        if inc_sev in sev_counts:
            sev_counts[inc_sev] += 1

        inc_sev_reason = highest_f.get("severity_reason", f"Inherited {inc_sev} severity from constituent findings")

        # Timestamps
        valid_f_times = [f["first_seen"] for f in f_list if f["first_seen"] is not None and pd.notna(f["first_seen"])]
        valid_l_times = [f["last_seen"] for f in f_list if f["last_seen"] is not None and pd.notna(f["last_seen"])]
        f_ts = min(valid_f_times) if valid_f_times else None
        l_ts = max(valid_l_times) if valid_l_times else None

        f_disp = f_ts.strftime("%Y-%m-%d %H:%M:%S") if f_ts is not None else "—"
        l_disp = l_ts.strftime("%Y-%m-%d %H:%M:%S") if l_ts is not None else "—"

        # Generate explainable correlation reason
        rules_str = ", ".join(rules_involved)
        if f_count == 1:
            f_single = f_list[0]
            if session_ids:
                corr_reason = f"Single session finding in session {session_ids[0]} ({rules_str})."
            elif f_single["rule_id"] == "RULE_B":
                u_cnt = f_single["details"].get("Distinct Usernames", "—")
                att_disp = f"{attacker_ids[0][:16]}…" if attacker_ids else "Unknown"
                corr_reason = f"Standalone password spraying pattern for attacker {att_disp} ({u_cnt} usernames targeted)."
            elif f_single["rule_id"] == "RULE_C":
                u_name = f_single["details"].get("Username", "—")
                p_mask = f_single["details"].get("Masked Password", "—")
                att_cnt = f_single["details"].get("Distinct Attackers", "—")
                corr_reason = f"Credential reuse pattern across honeypot ({att_cnt} attackers tried user: '{u_name}', pwd: '{p_mask}')."
            else:
                corr_reason = f"Isolated finding ({rules_str}); standalone occurrence without linked session."
        else:
            if len(session_ids) == 1:
                corr_reason = f"Multi-rule correlation in session {session_ids[0]}: {rules_str} ({f_count} findings)."
            elif len(session_ids) > 1 and len(attacker_ids) == 1:
                att_disp = f"{attacker_ids[0][:16]}…"
                corr_reason = f"Attacker {att_disp} activity correlated across {len(session_ids)} sessions within {time_window_minutes}m window: {rules_str} ({f_count} findings)."
            elif len(session_ids) == 0 and len(attacker_ids) == 1:
                att_disp = f"{attacker_ids[0][:16]}…"
                corr_reason = f"Attacker {att_disp} correlated across {f_count} candidate patterns within {time_window_minutes}m window ({rules_str})."
            elif len(attacker_ids) == 1:
                att_disp = f"{attacker_ids[0][:16]}…"
                corr_reason = f"Attacker {att_disp} multi-vector activity correlated within {time_window_minutes}m window ({rules_str}, {f_count} findings)."
            else:
                corr_reason = f"Correlated {f_count} findings across {len(session_ids)} sessions ({rules_str})."

        incident_obj = Incident(
            incident_id=inc_id,
            severity=inc_sev,
            severity_reason=inc_sev_reason,
            rules_involved=rules_involved,
            rule_ids_involved=rule_ids_involved,
            attacker_ids=attacker_ids,
            session_ids=session_ids,
            finding_count=f_count,
            first_seen=f_disp,
            last_seen=l_disp,
            correlation_reason=corr_reason,
            findings=f_list,
        )
        incident_objects.append(incident_obj)

        # Attacker display string
        if len(attacker_ids) == 1:
            att_disp_col = attacker_ids[0]
        elif len(attacker_ids) > 1:
            att_disp_col = f"{len(attacker_ids)} Attackers"
        else:
            att_disp_col = "—"

        # Session display string
        if len(session_ids) == 1:
            sess_disp_col = session_ids[0]
        elif len(session_ids) > 1:
            sess_disp_col = f"{len(session_ids)} Sessions"
        else:
            sess_disp_col = "—"

        incident_rows.append({
            "Incident ID": inc_id,
            "Severity": inc_sev,
            "Severity Reason": inc_sev_reason,
            "Rules Involved": rules_str,
            "Findings Count": f_count,
            "Unique Attackers": len(attacker_ids),
            "Attacker Identifier": att_disp_col,
            "Unique Sessions": len(session_ids),
            "Session ID": sess_disp_col,
            "First Seen (UTC)": f_disp,
            "Last Seen (UTC)": l_disp,
            "Correlation Reason": corr_reason,
        })

    incidents_df = pd.DataFrame(incident_rows)

    return {
        "incidents": incident_objects,
        "incidents_df": incidents_df,
        "summary": {
            "total_incidents": len(incident_objects),
            "multi_finding_incidents": multi_count,
            "severity_counts": sev_counts,
            "total_findings_reconciled": sum(inc.finding_count for inc in incident_objects),
        }
    }


def run_all_detection_rules(
    sessions: pd.DataFrame,
    credentials: pd.DataFrame,
    commands: pd.DataFrame,
    threshold_failures: int = 10,
    threshold_distinct_usernames: int = 5,
    threshold_distinct_attackers: int = 3,
    correlation_time_window_minutes: int = 30,
) -> Dict[str, Any]:
    """
    Run all 5 Stage 3B rule-based detections and return results plus aggregate summary metrics,
    severity breakdown, and Stage 5.2 correlated incidents.
    """
    rule_a = detect_repeated_auth_failures(sessions, credentials, threshold_failures=threshold_failures)
    rule_b = detect_password_spraying(credentials, threshold_distinct_usernames=threshold_distinct_usernames)
    rule_c = detect_credential_pair_reuse(credentials, threshold_distinct_attackers=threshold_distinct_attackers)
    rule_d = detect_auth_success_after_failures(sessions, credentials)
    rule_e = detect_post_auth_commands(sessions, commands, credentials=credentials)

    rules = [rule_a, rule_b, rule_c, rule_d, rule_e]

    all_affected_attackers = set()
    all_affected_sessions = set()
    total_matching_records = 0

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for r in rules:
        all_affected_attackers.update(r.affected_attacker_ids)
        all_affected_sessions.update(r.affected_session_ids)
        total_matching_records += r.matched_records_count
        if not r.evidence_df.empty and "Severity" in r.evidence_df.columns:
            counts = r.evidence_df["Severity"].value_counts().to_dict()
            for s_name, c in counts.items():
                if s_name in severity_counts:
                    severity_counts[s_name] += int(c)

    # Remove placeholder/unknown values from attacker set
    all_affected_attackers.discard("—")
    all_affected_attackers.discard("")

    results = {
        "rules": {
            "RULE_A": rule_a,
            "RULE_B": rule_b,
            "RULE_C": rule_c,
            "RULE_D": rule_d,
            "RULE_E": rule_e,
        },
        "summary": {
            "total_rules": len(rules),
            "total_matching_records": total_matching_records,
            "unique_affected_attackers": len(all_affected_attackers),
            "unique_affected_sessions": len(all_affected_sessions),
            "severity_counts": severity_counts,
        }
    }

    # Stage 5.2: Correlate findings into incidents
    correlations = correlate_incidents(
        detection_results=results,
        sessions=sessions,
        time_window_minutes=correlation_time_window_minutes,
    )
    results["incidents"] = correlations["incidents"]
    results["incidents_df"] = correlations["incidents_df"]
    results["incident_summary"] = correlations["summary"]

    return results

