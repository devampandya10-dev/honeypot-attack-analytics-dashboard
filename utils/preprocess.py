"""
utils/preprocess.py

Real honeypot dataset cleaning and normalization pipeline.
Processes data/raw/cyberlab_2020-02-07.json.gz into optimized Parquet tables.
"""

import gzip
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
DEFAULT_RAW_FILE = RAW_DIR / "cyberlab_2020-02-07.json.gz"


def process_cyberlab_dataset(
    raw_path: Path | str | None = None,
    output_dir: Path | str | None = None,
    force: bool = False,
) -> dict[str, Path]:
    """
    Clean, normalize, and export the CyberLab/Cowrie honeypot dataset.

    Generates 5 optimized Parquet datasets in output_dir:
      1. events.parquet       — All 1.37M clean event-level records
      2. sessions.parquet     — 284K session-level aggregated records
      3. credentials.parquet  — 287K authentication attempt records
      4. commands.parquet     — 436 interactive command input records
      5. attackers.parquet    — 4,110 unique attacker profiles

    Returns dict of table name -> saved Parquet Path.
    """
    input_file = Path(raw_path) if raw_path else DEFAULT_RAW_FILE
    out_dir = Path(output_dir) if output_dir else PROCESSED_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    target_files = {
        "events": out_dir / "events.parquet",
        "sessions": out_dir / "sessions.parquet",
        "credentials": out_dir / "credentials.parquet",
        "commands": out_dir / "commands.parquet",
        "attackers": out_dir / "attackers.parquet",
    }

    # Check if already processed
    if not force and all(p.exists() for p in target_files.values()):
        logger.info("Processed Parquet datasets already exist. Skipping re-processing.")
        return target_files

    if not input_file.exists():
        raise FileNotFoundError(f"Raw dataset file not found at: {input_file}")

    logger.info(f"Starting raw dataset processing from: {input_file}")

    # Accumulators for event-level records
    event_rows: list[dict[str, Any]] = []
    auth_rows: list[dict[str, Any]] = []
    cmd_rows: list[dict[str, Any]] = []
    session_rows: list[dict[str, Any]] = []

    # Stream the gzip file line by line
    with gzip.open(input_file, "rt", encoding="utf-8") as f:
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
                session_obj = json.loads(line)
            except Exception:
                continue

            for session_id, events in session_obj.items():
                if not events:
                    continue

                # Session-level tracking variables
                sess_src_ip = None
                sess_sensor = None
                sess_country = None
                sess_cc2 = None
                sess_city = None
                sess_lat = None
                sess_lon = None
                sess_start_ts = None
                sess_end_ts = None
                sess_duration = None
                failed_logins = 0
                successful_logins = 0
                cmd_count = 0

                for ev in events:
                    ev_id = ev.get("eventid")
                    ts = ev.get("timestamp")
                    src_ip = ev.get("src_ip_identifier")
                    sensor = ev.get("sensor")
                    proto = ev.get("protocol")
                    port = ev.get("src_port")
                    uname = ev.get("username")
                    pwd = ev.get("password")
                    msg = ev.get("message")
                    duration = ev.get("duration")
                    ssh_ver = ev.get("ssh_client_version")

                    # Flatten geolocation_data
                    geo = ev.get("geolocation_data")
                    c_name = None
                    c_code = None
                    city = None
                    lat = None
                    lon = None

                    if isinstance(geo, dict):
                        c_name = geo.get("country_name")
                        c_code = geo.get("country_code2")
                        city = geo.get("city_name")
                        lat = geo.get("latitude")
                        lon = geo.get("longitude")

                    # Capture session attributes from first available event
                    if sess_src_ip is None and src_ip:
                        sess_src_ip = src_ip
                    if sess_sensor is None and sensor:
                        sess_sensor = sensor
                    if sess_country is None and c_name:
                        sess_country = c_name
                    if sess_cc2 is None and c_code:
                        sess_cc2 = c_code
                    if sess_city is None and city:
                        sess_city = city
                    if sess_lat is None and lat:
                        sess_lat = lat
                    if sess_lon is None and lon:
                        sess_lon = lon

                    if ts:
                        if sess_start_ts is None:
                            sess_start_ts = ts
                        sess_end_ts = ts

                    if duration is not None:
                        sess_duration = duration

                    # 1. Clean event-level record
                    event_record = {
                        "timestamp": ts,
                        "eventid": ev_id,
                        "session_id": session_id,
                        "src_ip_identifier": src_ip,
                        "protocol": proto,
                        "src_port": port,
                        "username": uname,
                        "password": pwd,
                        "message": msg,
                        "sensor": sensor,
                        "country_name": c_name,
                        "country_code2": c_code,
                        "city_name": city,
                        "latitude": lat,
                        "longitude": lon,
                        "duration": duration,
                        "ssh_client_version": ssh_ver,
                    }
                    event_rows.append(event_record)

                    # 2. Authentication events (cowrie.login.failed, cowrie.login.success)
                    if ev_id in ("cowrie.login.failed", "cowrie.login.success"):
                        is_success = ev_id == "cowrie.login.success"
                        if is_success:
                            successful_logins += 1
                        else:
                            failed_logins += 1

                        auth_rows.append({
                            "timestamp": ts,
                            "session_id": session_id,
                            "src_ip_identifier": src_ip,
                            "username": uname,
                            "password": pwd,
                            "login_success": is_success,
                            "country_name": c_name,
                            "country_code2": c_code,
                            "city_name": city,
                            "sensor": sensor,
                        })

                    # 3. Command events (cowrie.command.input)
                    elif ev_id == "cowrie.command.input":
                        cmd_count += 1
                        raw_cmd = msg or ""
                        clean_cmd = raw_cmd[5:].strip() if raw_cmd.startswith("CMD: ") else raw_cmd.strip()

                        cmd_rows.append({
                            "timestamp": ts,
                            "session_id": session_id,
                            "src_ip_identifier": src_ip,
                            "command": clean_cmd,
                            "raw_message": raw_cmd,
                            "username": uname,
                            "country_name": c_name,
                            "country_code2": c_code,
                            "city_name": city,
                            "sensor": sensor,
                        })

                # Session record
                session_rows.append({
                    "session_id": session_id,
                    "src_ip_identifier": sess_src_ip,
                    "start_time": sess_start_ts,
                    "end_time": sess_end_ts,
                    "duration": sess_duration,
                    "event_count": len(events),
                    "login_attempts": failed_logins + successful_logins,
                    "failed_logins": failed_logins,
                    "successful_logins": successful_logins,
                    "has_login_success": successful_logins > 0,
                    "command_count": cmd_count,
                    "country_name": sess_country,
                    "country_code2": sess_cc2,
                    "city_name": sess_city,
                    "latitude": sess_lat,
                    "longitude": sess_lon,
                    "sensor": sess_sensor,
                })

    logger.info("Conversion to DataFrames and type casting...")

    # Build Events DataFrame
    df_events = pd.DataFrame(event_rows)
    df_events["timestamp"] = pd.to_datetime(df_events["timestamp"], utc=True)
    df_events["src_port"] = pd.to_numeric(df_events["src_port"], downcast="integer")
    df_events["duration"] = pd.to_numeric(df_events["duration"], downcast="float")
    df_events["latitude"] = pd.to_numeric(df_events["latitude"], downcast="float")
    df_events["longitude"] = pd.to_numeric(df_events["longitude"], downcast="float")
    df_events.to_parquet(target_files["events"], index=False, engine="pyarrow", compression="snappy")
    logger.info(f"Saved {len(df_events):,} records to {target_files['events']}")
    del event_rows

    # Build Sessions DataFrame
    df_sessions = pd.DataFrame(session_rows)
    df_sessions["start_time"] = pd.to_datetime(df_sessions["start_time"], utc=True)
    df_sessions["end_time"] = pd.to_datetime(df_sessions["end_time"], utc=True)
    df_sessions["duration"] = pd.to_numeric(df_sessions["duration"], downcast="float")
    df_sessions["latitude"] = pd.to_numeric(df_sessions["latitude"], downcast="float")
    df_sessions["longitude"] = pd.to_numeric(df_sessions["longitude"], downcast="float")
    df_sessions.to_parquet(target_files["sessions"], index=False, engine="pyarrow", compression="snappy")
    logger.info(f"Saved {len(df_sessions):,} records to {target_files['sessions']}")
    del session_rows

    # Build Credentials (Authentication) DataFrame
    df_creds = pd.DataFrame(auth_rows)
    if not df_creds.empty:
        df_creds["timestamp"] = pd.to_datetime(df_creds["timestamp"], utc=True)
        df_creds["login_success"] = df_creds["login_success"].astype(bool)
    df_creds.to_parquet(target_files["credentials"], index=False, engine="pyarrow", compression="snappy")
    logger.info(f"Saved {len(df_creds):,} records to {target_files['credentials']}")
    del auth_rows

    # Build Commands DataFrame
    df_cmds = pd.DataFrame(cmd_rows)
    if not df_cmds.empty:
        df_cmds["timestamp"] = pd.to_datetime(df_cmds["timestamp"], utc=True)
    df_cmds.to_parquet(target_files["commands"], index=False, engine="pyarrow", compression="snappy")
    logger.info(f"Saved {len(df_cmds):,} records to {target_files['commands']}")
    del cmd_rows

    # Build Attackers (Geography & IP Profiles) DataFrame
    logger.info("Computing attacker summary profiles...")
    df_attackers = (
        df_sessions.groupby("src_ip_identifier", as_index=False)
        .agg(
            country_name=("country_name", "first"),
            country_code2=("country_code2", "first"),
            city_name=("city_name", "first"),
            latitude=("latitude", "first"),
            longitude=("longitude", "first"),
            first_seen=("start_time", "min"),
            last_seen=("end_time", "max"),
            total_sessions=("session_id", "count"),
            total_events=("event_count", "sum"),
            total_login_attempts=("login_attempts", "sum"),
            failed_logins=("failed_logins", "sum"),
            successful_logins=("successful_logins", "sum"),
            total_commands=("command_count", "sum"),
        )
    )
    df_attackers.to_parquet(target_files["attackers"], index=False, engine="pyarrow", compression="snappy")
    logger.info(f"Saved {len(df_attackers):,} records to {target_files['attackers']}")

    logger.info("Preprocessing complete! All Parquet datasets generated successfully.")
    return target_files


if __name__ == "__main__":
    process_cyberlab_dataset(force=True)
