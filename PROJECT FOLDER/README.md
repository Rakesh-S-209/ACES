<div align="center">

# ▲ A.C.E.S.
### Autonomous Cyber-defence & Enforcement System

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?logo=sqlite&logoColor=white)](https://sqlite.org)


*A production-grade Zero Trust security platform with AI-driven anomaly detection, multi-layer deception infrastructure, and a live SOC analyst dashboard.*

</div>

---

## What is A.C.E.S.?

A.C.E.S. simulates a corporate financial portal — **NorthStar Capital** — defended by three simultaneous detection layers. Every incoming connection, file access, and user click is monitored in real time. Threats are contained automatically in under 5ms while a SOC analyst watches the full attack unfold on a live dashboard.

```
Kali Linux Attacker
        │
        ├─ nmap / nc ──────▶ PortTrap (ports 22, 445, 3389)
        │                        └─ instant IP ban + SOC alert
        │
        ├─ gobuster ───────▶ Web Honeytoken Paths (40+ bait URLs)
        │                        └─ instant IP ban + SOC alert
        │
        └─ browser ────────▶ Financial Portal (port 8000)
                                 ├─ IP ban check → 403 quarantine
                                 ├─ BehaviorScorer (IsolationForest)
                                 │    score ≥ 0.50 → SOC alert
                                 │    score ≥ 0.85 → auto-ban + revoke
                                 └─ WebSocket → SOC Dashboard
```

---

## Detection Layers

| Layer | Mechanism | What it catches | Response time |
|---|---|---|---|
| **PortTrap** | `asyncio` TCP honeypot on ports 22, 445, 3389 | Nmap scans, port probes | < 5 ms |
| **HoneytokenWatcher** | `watchdog` filesystem monitor on `db_config.json` | Credential file access | < 10 ms |
| **Web Honeytokens** | 40+ bait HTTP paths (`/.env`, `/wp-admin`, etc.) | Gobuster / Dirbuster scans | < 5 ms |
| **BehaviorScorer** | IsolationForest on 29 network flow features | Anomalous click patterns, rapid request rates | < 100 ms |

---

## SOC Dashboard

Five live analytical pages, all role-gated to the `engineer` account:

| Page | What it shows |
|---|---|
| **Active Logs** | Real-time WebSocket event stream + Top 5 volatile IPs |
| **Triage Queue** | All security events with unread badge, per-event investigation panel |
| **Deception & Honeytokens** | Port status, honeytoken trip history, SOAR mode toggle, port management |
| **Score Distribution** | KDE chart — benign traffic vs attack traffic scored by the production model |
| **Baseline Timeline** | Live time-series of anomaly score vs 0.50 threshold, auto-updating every 5s |

---

## ML Model

The `BehaviorScorer` uses a **scikit-learn IsolationForest** trained on real network flow data.

| Property | Value |
|---|---|
| **Dataset** | CIC-IoT-2023 — BenignTraffic.pcap.csv |
| **Training samples** | 362,361 real benign flows |
| **Features** | 29 (Rate, IAT, TCP flags, packet sizes, protocol presence) |
| **Preprocessing** | `RobustScaler` (median/IQR — handles long-tailed distributions) |
| **Estimators** | 200 trees |
| **Contamination** | 0.02 (2%) |
| **Scoring formula** | `score = 0.5 − clip(decision_function(X), −0.5, +0.5)` |
| **Thresholds** | ≥ 0.50 → SOC alert · ≥ 0.85 → auto-containment |

**Score ranges from real data:**
- Benign traffic: **0.05 – 0.25** (well below threshold)
- Scanner traffic: **0.70 – 1.0** (above both thresholds)

---

## Project Structure

```
Final capstone project/
├── run.py                          # Entry point — starts all 4 subsystems
├── train_behavior_model.py         # Offline model trainer (run once)
├── requirements.txt                # Pinned Python dependencies
├── .env.example                    # Environment variable template
│
├── src/
│   ├── zero_trust/
│   │   ├── scorer.py               # BehaviorScorer (IsolationForest)
│   │   ├── models.py               # Core dataclasses and enums
│   │   └── validation.py           # TelemetryVector field validators
│   │
│   ├── soc_pipeline/
│   │   ├── ws_dashboard.py         # HTTP + WebSocket server (all routes)
│   │   ├── soar_engine.py          # SOAR automation engine
│   │   ├── event_hub.py            # asyncio pub/sub event bus
│   │   ├── intel_aggregator.py     # AbuseIPDB + offline fallback
│   │   └── abuseipdb_client.py     # AbuseIPDB v2 API client
│   │
│   ├── deception/
│   │   ├── port_trap.py            # Multi-port TCP honeypot daemon
│   │   └── token_watcher.py        # Filesystem honeytoken watcher
│   │
│   ├── portal/
│   │   ├── financial_shell.py      # Portal action handler + scorer
│   │   ├── gateway.py              # BasePortalShell + IP ban middleware
│   │   └── static/
│   │       ├── index.html          # Landing page / login / signup
│   │       ├── portal.html         # Financial portal (employee + admin)
│   │       └── soc.html            # SOC analyst dashboard
│   │
│   └── auth/
│       └── db.py                   # SQLite auth, sessions, bans, event logs
│
├── data/
│   ├── behavior_model.pkl          # Trained model (generated by trainer)
│   ├── honey_tokens/
│   │   └── db_config.json          # Decoy credential file (honeytoken bait)
│   └── aces_production.db          # SQLite database (runtime state)
│
├── tests/                          # Property-based + integration tests
├── frontend-aces/                  # React/Vite frontend (supplementary)
├── COURSE_REPORT.md                # Full project report (Markdown)
└── COURSE_REPORT.docx              # Full project report (Word document)
```

---

## Quick Start

### 1. Prerequisites

```bash
# Python 3.11+
python --version

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure environment

```bash
# Copy the template
copy .env.example .env

# Edit .env — set your AbuseIPDB API key (optional, mock mode works without it)
# ABUSEIPDB_API_KEY=your_key_here
# ACES_ENV=development
# ACES_MONITOR_ONLY=0
```

### 3. Train the ML model (first run only)

```bash
# Requires ~/Downloads/BenignTraffic.pcap.csv
# Download from: https://www.unb.ca/cic/datasets/iotdataset-2023.html
python train_behavior_model.py
```

If the CSV isn't available, `run.py` falls back to a synthetic baseline automatically.

### 4. Start the server

```bash
python run.py
```

The server starts four subsystems simultaneously:

| Task | What starts |
|---|---|
| **A** | `HoneytokenWatcher` — watchdog daemon on `data/honey_tokens/` |
| **B** | `SOAREngine` — async threat orchestrator |
| **C** | `PortTrap` — TCP honeypots on ports 3389, 22, 445 |
| **D** | `SOCDashboardServer` — HTTP + WebSocket on port 8000 |

### 5. Open in browser

```
Corporate Portal  →  http://<your-ip>:8000/app/home
SOC Dashboard     →  http://<your-ip>:8000/app/soc-board
```

---

## Built-in Accounts

| Username | Password | Role | Access |
|---|---|---|---|
| `soc_engineer` | `EngineerPass3!` | Engineer | SOC dashboard only |
| `admin_user` | `AdminPass3!` | Admin | Corporate portal admin panel |
| `employee_test` | `EmployeeSecure123!` | User | Financial portal only |

---

## Live Attack Demo (Kali Linux)

Run these from a Kali VM on the same network to trigger real alerts on the SOC dashboard:

```bash
# 1. Port trap — triggers instant IP ban
nmap -sT -p 3389 <target-ip>
nc -z <target-ip> 3389

# 2. Web honeytoken — triggers instant ban
curl http://<target-ip>:8000/.env
curl http://<target-ip>:8000/wp-admin

# 3. Directory scan — each path hits a bait route
gobuster dir -u http://<target-ip>:8000 -w /usr/share/wordlists/dirb/common.txt

# 4. Verify ban is in effect
curl -v http://<target-ip>:8000/app/home
# Expected: HTTP 403 "Access Revoked" quarantine page
```

> **Note:** Run `run.py` as Administrator on Windows for ports 22 and 445 to bind. Port 3389 works without elevation.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB API key. Leave empty for offline mock mode. |
| `ACES_ENV` | `development` | Environment flag. Controls CORS and debug logging. |
| `ACES_MONITOR_ONLY` | `0` | Set to `1` to log threats without banning. Use for live demos. |
| `ACES_HONEYPORT_LIST` | `3389,22,445` | Comma-separated list of TCP honeypot ports. |

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test files
pytest tests/test_scorer.py -v
pytest tests/test_soar.py -v
pytest tests/test_deception.py -v

# Property-based tests (uses Hypothesis)
pytest tests/test_models.py tests/test_validation.py -v
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, asyncio (no framework) |
| ML | scikit-learn IsolationForest, RobustScaler, joblib |
| Database | SQLite WAL mode, threading.Lock |
| Real-time | WebSocket (RFC 6455, manual implementation) |
| Frontend | HTML5, CSS3, Vanilla JS, Chart.js 4.4 |
| Deception | watchdog, asyncio TCP server |
| Testing | pytest, pytest-asyncio, Hypothesis |
| Dataset | CIC-IoT-2023 (University of New Brunswick) |

---

---

<div align="center">

Built as the final capstone project for the **SURE Trust Cybersecurity** programme.

*"Zero bytes sent. Zero data leaked. Zero Trust enforced."*

</div>
