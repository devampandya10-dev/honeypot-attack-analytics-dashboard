# Honeypot Attack Analytics Dashboard

A threat intelligence and behavioral analytics platform for analyzing Cowrie SSH/Telnet honeypot telemetry. Built with Python, Streamlit, and Plotly, this platform transforms high-volume, unstructured honeypot logs into actionable security intelligence through heuristic detection rules, incident correlation, temporal profiling, and credential attack analysis.

Designed as an end-to-end B.Tech Cybersecurity Capstone / Portfolio Project demonstrating practical skills in threat detection, log analytics, security data visualization, and incident triage.

---

## Table of Contents
1. [Project Overview & Objectives](#project-overview--objectives)
2. [Technologies Used](#technologies-used)
3. [Architecture & Project Structure](#architecture--project-structure)
4. [Dataset Source & Attribution](#dataset-source--attribution)
5. [Installation & Setup](#installation--setup)
6. [Running the Application](#running-the-application)
7. [Operating Modes: Real Data vs Demo Data](#operating-modes-real-data-vs-demo-data)
8. [Dashboard Views & Features](#dashboard-views--features)
9. [Threat Detection Rules (A–E)](#threat-detection-rules-a--e)
10. [Severity Classification & Incident Correlation](#severity-classification--incident-correlation)
11. [Testing & Quality Assurance](#testing--quality-assurance)
12. [False-Positive Considerations & Limitations](#false-positive-considerations--limitations)
13. [Security & Privacy Principles](#security--privacy-principles)

---

## Project Overview & Objectives

Internet-facing honeypots passively capture automated reconnaissance, credential brute-forcing, and post-compromise commands from botnets, worms, and adversaries. However, raw honeypot logs (often millions of JSON events) are noisy, redundant, and difficult for security analysts to triage manually.

### Key Objectives
* **Telemetry Processing:** Clean and normalize 1.37M+ raw honeypot events into performant, column-oriented Parquet datasets.
* **Attack Surface Profiling:** Quantify attacker activity concentration (Pareto distribution), temporal spikes, and global origin footprints.
* **Credential Defense Analysis:** Analyze targeted usernames, password dictionaries, and credential reuse across disparate attackers without exposing sensitive credentials in the UI.
* **Heuristic Detection Engine:** Implement five rule-based detection algorithms identifying brute-force bursts, horizontal password spraying, credential pair reuse, compromised logins, and interactive shell execution.
* **Incident Correlation & Triage:** Correlate disparate detection findings by attacker entity and temporal proximity into cohesive security incidents with automated investigation summaries and timeline reconstruction.

---

## Technologies Used

* **Frontend & Visualization:** [Streamlit](https://streamlit.io/) (interactive web application), [Plotly](https://plotly.com/python/) (dynamic interactive charts and Pareto graphs).
* **Data Processing & Analytics:** [Python 3.10+](https://www.python.org/), [Pandas](https://pandas.pydata.org/) (data wrangling, aggregations, time-series resampling), [NumPy](https://numpy.org/) (numerical binning), [PyArrow / FastParquet](https://arrow.apache.org/docs/python/) (high-performance columnar storage).
* **Testing & Verification:** Python `unittest` framework (18 unit tests covering detection rules, correlation windows, severity scoring, and data boundaries).

---

## Architecture & Project Structure

```
honeypot-dashboard/
├── app.py                      # Application entry point, styling, sidebar & routing
├── requirements.txt            # Python package dependencies
├── README.md                   # Project documentation
│
├── data/
│   ├── raw/                    # Original raw dataset (cyberlab_2020-02-07.json.gz)
│   └── processed/              # Normalized, columnar Parquet tables:
│       ├── events.parquet      # 1,374,742 clean event records
│       ├── sessions.parquet    # 284,918 aggregated session lifespans
│       ├── credentials.parquet # 287,761 authentication attempt records
│       ├── commands.parquet    # 436 interactive shell executions
│       └── attackers.parquet   # 4,110 unique attacker profiles
│
├── views/                      # Modular dashboard view renderers
│   ├── overview.py             # View 1: Security Overview & telemetry KPIs
│   ├── attackers.py            # View 2: Attacker profiles & Pareto analysis
│   ├── timeline.py             # View 3: Attack timeline & session lifespans
│   ├── credentials.py          # View 4: Credential attack intelligence
│   ├── behavior.py             # View 5: Interactive command & payload analysis
│   ├── geography.py            # View 6: Global origin & country distribution
│   └── anomalies.py            # View 7: Threat detection rules & incidents
│
├── utils/                      # Core data pipeline & business logic
│   ├── data_loader.py          # Dual-mode data loader (Demo / Real) with caching
│   ├── preprocess.py           # Raw JSON.gz parsing & Parquet generation pipeline
│   ├── detection_rules.py      # Rules A–E engine & incident correlation logic
│   └── ui.py                   # Shared UI components, color palette & Plotly templates
│
└── tests/
    └── test_detection_rules.py # 18 unit tests verifying detection & correlation
```

---

## Dataset Source & Attribution

* **Source Dataset:** CyberLab Cowrie Honeypot Capture (`cyberlab_2020-02-07.json.gz`).
* **Sensor Type:** Cowrie medium-interaction SSH and Telnet honeypot.
* **Observation Period:** 2020-02-07 00:00:01 UTC to 2020-02-08 00:01:45 UTC (24.03 hours observed).
* **Verified Real Dataset Metrics:**
  * **Total Events:** 1,374,742 raw interaction events.
  * **Total Sessions:** 284,918 distinct connection sessions.
  * **Unique Attacker Identifiers:** 4,110 source entities (`src_ip_identifier`).
  * **Authentication Attempts:** 287,761 total attempts (282,621 failed, 5,140 successful; 1.79% success rate).
  * **Session Authentication Activity:** 244,473 sessions with authentication activity (239,333 failed attempts only; 5,119 successful attempts only; 21 with both).
  * **Interactive Commands:** 436 shell command inputs across 67 unique command strings and 44 distinct attackers.
  * **Geolocation Coverage:** 1,347,048 events ($97.99\%$) geolocated across 123 countries.

---

## Installation & Setup

### Prerequisites
* Python 3.10, 3.11, or 3.12 (Python 3.10+ recommended)
* `git` (optional, for cloning)

### 1. Clone the Repository
```bash
git clone https://github.com/devampandya10-dev/honeypot-attack-analytics-dashboard.git
cd honeypot-attack-analytics-dashboard
```

### 2. Create and Activate a Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. (Optional) Run Preprocessing Pipeline
If starting from a raw `cyberlab_2020-02-07.json.gz` file located in `data/raw/`:
```bash
python -m utils.preprocess
```
*Note: If pre-generated Parquet tables already exist in `data/processed/`, this step is automatically skipped.*

---

## Running the Application

Launch the Streamlit interface:
```bash
streamlit run app.py
```

Once started, open your web browser to:
```
http://localhost:8501
```

---

## Operating Modes: Real Data vs Demo Data

The dashboard supports an instant, seamless runtime toggle located in the sidebar:

| Feature | Real Data Mode (`CyberLab`) | Demo Data Mode (`Synthetic`) |
| :--- | :--- | :--- |
| **Primary Use Case** | Deep-dive telemetry analysis & research | Quick demonstration, testing & offline demos |
| **Data Source** | Columnar Parquet tables in `data/processed/` | In-memory synthetic generator in `data_loader.py` |
| **Volume** | 1,374,742 events · 284,918 sessions | 291 events · 35 sessions |
| **Detection Findings** | 37,426 findings · 35,424 correlated incidents | 37 correlated incidents |
| **Memory Footprint** | Efficiently streamed via PyArrow (~100 MB RAM) | Minimal (< 10 MB RAM) |

---

## Dashboard Views & Features

### 1. Security Overview (`views/overview.py`)
* **Executive Metrics:** Total Events, Unique Attackers, Total Sessions, Login Attempts, Overall Success Rate, and Post-Auth Commands.
* **Telemetry Breakdown:** Event type breakdown (connections, authentication attempts, closed sessions) and protocol distribution (SSH vs. Telnet).
* **Hourly Trend:** 24-hour activity distribution tracking activity surges across UTC boundaries.

### 2. Attacker Analysis (`views/attackers.py`)
* **Attacker Profiling:** Identifies most active attacker entities, total events, country of origin, and average activity per attacker.
* **Pareto Concentration:** Quantifies attack concentration (Top 1: 3.55%, Top 10: 23.18%, Top 20: 31.55% of all events) with cumulative activity charts.
* **Authentication Outcomes:** Classifies attackers into failed-only, successful-login, shell-active, and non-authenticating scan probes.
* **Searchable Profile Table:** Filterable table displaying attacker IP identifiers, country, total events, session counts, and empirical first/last seen timestamps.

### 3. Attack Timeline (`views/timeline.py`)
* **Temporal Intelligence:** Identifies Peak Activity Day, Peak Event Hour (10:00 UTC with 90,264 events), and empirical event density (57,212 events/hour over 24.0h observed).
* **Interactive Timeline:** Zoomable temporal chart with adjustable granularity (Hourly, Daily, Weekly).
* **Session Lifespan Metrics:** Median session duration (2.82s), 95th percentile duration (26.84s), and duration distribution histogram across 278,600 sessions with verified termination timestamps.
* **Session Auth Funnel:** Clear breakdown of authentication activity across sessions (239,333 failed only, 5,119 successful only, 21 both).

### 4. Credential Attacks (`views/credentials.py`)
* **Credential Attempt Intelligence:** Total Login Attempts (287,761), Failed Attempts (282,621), Successful Logins (5,140), and Success Rate ($1.79\%$).
* **Target Profiling:** Most targeted usernames (e.g., `root`, `admin`, `default`) and password dictionary frequencies.
* **Top Credential Pairs:** Detailed matrix of `(username, password)` combinations with independent success and failure counts.
* **Password Privacy:** Enforces strict privacy controls by masking all credential strings in UI charts and tables (`[REDACTED]` or `Credential #N`).

### 5. Command & Behavior (`views/behavior.py`)
* **Post-Exploitation Analytics:** Total Commands Executed (436), Unique Command Strings (67), Attackers Executing Commands (44), and Sessions with Commands (303).
* **Behavioral Categorization:** Deterministic keyword categorization engine mapping commands to:
  * *Reconnaissance & Enumeration* (`uname -a`, `cat /proc/cpuinfo`)
  * *Malware Download & Staging* (`wget`, `curl`, staging scripts)
  * *System Alteration & Execution* (`chmod +x`, `./up-to-date01`)
  * *Defense Evasion & Log Wiping* (`history -c`)
* **Command Frequency Table:** Chronological and frequency breakdowns of adversarial activity.

### 6. Geographical Analysis (`views/geography.py`)
* **Global Threat Footprint:** Top Attacking Country, Geolocated Events ($1,347,048$ / $97.99\%$), Ungeolocated Events ($27,694$ / $2.01\%$), and Unique Countries (123).
* **Geographic Distribution:** Bar charts and tables showing country representation by ISO alpha-2 codes and event volume.

### 7. Threat Detection & Incidents (`views/anomalies.py`)
* **Detection Engine:** Executes Rules A–E with configurable sidebar thresholds and an incident correlation time window.
* **Pipeline Caching:** Cached with `@st.cache_data` keyed by threshold values and data mode, ensuring immediate UI filtering without recalculation overhead.
* **Incident Table:** Filterable by severity (High / Medium / Low), rule triggers, and entity search.
* **Interactive Investigation Panel:**
  * **Investigation Summary:** Dynamic briefing describing triggered rules, entity counts, timestamps, and correlation rationale.
  * **Evidence Explorer:** Tabular inspection of individual rule findings.
  * **Session Timeline:** Chronological step-by-step reconstruction of connection, authentication, and command events within associated sessions.

---

## Threat Detection Rules (A–E)

The detection pipeline runs five deterministic heuristic detection rules:

| Rule ID | Rule Name | Detection Target | Default Threshold |
| :---: | :--- | :--- | :---: |
| **RULE_A** | **Repeated Authentication Failures** | Brute-force bursts within a single session | $\ge 10$ failed attempts |
| **RULE_B** | **Password Spraying Candidates** | Horizontal spray testing one password across distinct usernames | $\ge 5$ distinct usernames |
| **RULE_C** | **Credential Pair Reuse** | Distributed attacks testing identical `(user, pass)` from multiple IPs | $\ge 3$ distinct attackers |
| **RULE_D** | **Success After Failures** | Penetration / brute-force success preceded by failed attempts | $\ge 1$ failure before success |
| **RULE_E** | **Post-Auth Command Activity** | Successful authentication followed by interactive shell execution | $\ge 1$ command executed |

---

## Severity Classification & Incident Correlation

### Severity Engine
Findings and correlated incidents are categorized into three severity tiers:
* **High Severity:** Incidents involving confirmed system compromise (Rule D), post-exploitation shell command activity (Rule E), or multi-rule correlated attacks.
* **Medium Severity:** High-volume single-session brute-force attempts (Rule A), horizontal password spraying patterns (Rule B), or distributed credential reuse (Rule C).
* **Low Severity:** Informational or sub-threshold anomalous behaviors.

### Incident Correlation Logic
Individual findings rarely occur in isolation. The correlation engine groups findings based on:
1. **Attacker Entity:** Shared `src_ip_identifier`.
2. **Temporal Proximity:** Events occurring within the user-defined correlation window (default: 60 minutes).
3. **Multi-Session Clusters:** Multi-session behavioral patterns (Rules B and C) grouped by shared pattern entities, preserving relationships between attackers and affected sessions.

---

## Testing & Quality Assurance

The project includes an automated test suite verifying detection logic, threshold boundaries, incident correlation, and edge cases.

### Running Unit Tests
Execute the test runner from the project root:
```bash
python -m unittest discover tests
```

### Expected Output
```text
..................
----------------------------------------------------------------------
Ran 18 tests in 0.394s

OK
```

### Test Coverage Highlights
* **Rule Logic:** Tests for Rules A, B, C, D, and E with boundary condition verification.
* **Incident Correlation:** Verifies grouping within and outside the correlation window, ensuring zero lost or duplicate findings.
* **Empty / Edge Inputs:** Validates graceful handling of missing columns, null durations, and zero-session records.

---

## False-Positive Considerations & Limitations

> [!IMPORTANT]
> **Operational Principle:** Rule-based detections are **security indicators**, not conclusive proof of malicious intent. Honeypot telemetry reflects passive interactions that must be contextualized by security analysts.

### Rule A — Repeated Authentication Failures
* **Potential False Positives:** Automated service scripts or backup tasks attempting reconnection with outdated credentials; legitimate administrative lockouts.
* **Analyst Verification:** Check whether targeted usernames are generic defaults (`root`, `admin`) or recognized organizational accounts; inspect inter-attempt timing (machine-speed bursts < 1s vs. human typing).

### Rule B — Password Spraying Candidates
* **Potential False Positives:** Corporate egress proxies or NAT gateways multiplexing multiple legitimate users testing common organizational passwords; enterprise identity provisioning tests.
* **Analyst Verification:** Verify source IP reputation and gateway type; inspect username sorting (alphabetical ordering indicates automated dictionaries).

### Rule C — Credential Pair Reuse
* **Potential False Positives:** Pervasive factory-default credentials (`admin:admin`, `root:root`) attempted independently by uncoordinated botnets, IoT crawlers, or academic Internet scanners (e.g., Censys, Shadowserver).
* **Analyst Verification:** Determine whether the credential pair is a known commodity default or a specific high-entropy credential; analyze temporal and geographic spread.

### Rule D — Authentication Success After Failures
* **Potential False Positives:** An authorized operator mistyping a password on the initial attempt before entering the valid credential; SSH client cycling through multiple local private keys.
* **Analyst Verification:** Check preceding failure count (1 typo vs. dozens of dictionary attempts); verify if the successful username matches the failed user attempts; inspect subsequent command activity.

### Rule E — Post-Authentication Shell Command Activity
* **Potential False Positives:** Scheduled administrative playbooks (Ansible, Puppet) or monitoring probes running benign diagnostics (`uptime`, `uname -a`) on monitored jump hosts.
* **Analyst Verification:** Inspect command semantics (benign diagnostics vs. malware staging scripts via `wget`/`curl`, `chmod +x`, or log wiping); review execution cadence.

---

## Security & Privacy Principles

1. **Password Masking:** Raw passwords from honeypot captures are never rendered in dashboard charts, hover tooltips, summary cards, or incident tables. All UI displays utilize `[REDACTED]` or non-sensitive labels (`Credential #N`).
2. **Read-Only Telemetry:** The dashboard and processing scripts perform strictly read-only analytical queries. No telemetry or payload is executed on the host system.
3. **No External API Dependencies:** The heuristic detection rules, incident summaries, and analytics run entirely locally using deterministic algorithms, requiring no external cloud or AI services.

---

## License

This project is developed for educational, academic, and research purposes under the MIT License. Data captures from the CyberLab Cowrie Honeypot are used in accordance with academic research and open-telemetry sharing practices.
