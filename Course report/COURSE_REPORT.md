# SURE Trust — Project Report

**Innovation & Entrepreneurship Hub for Educated Rural Youth (SURE Trust – IERY)**

---

<div align="center">

## A.C.E.S – Autonomous Cyber-defence and Enforcement System

**Domain:** Cybersecurity

**Course:** Cybersecurity

</div>

---

## Team Details

| Role | Name | Signature |
|---|---|---|
| **Student** | Rakesh S | |
| **Mentor** | Mr. Derick Johnson, Cybersecurity Trainer, Sure ProEd | |

**Period:** February 2026 to August 2026

---

## Declaration

The project titled "Autonomous Cyber-defence & Enforcement System" has been mentored by Mr. Derick Johnson, organised by SURE Trust, from February 2026 to August 2026, for the benefit of the educated unemployed rural youth for gaining hands-on experience in working on industry relevant projects.

I declare that to the best of my knowledge the member of the team mentioned below has worked on it successfully and enhanced their practical knowledge in the domain.

**Mr. Rakesh S** — Signature: ___________________

**Mr. Derick Johnson**
Cybersecurity Trainer — Sure ProEd

**Prof. Radhakumari**
Executive Director & Founder — SURE Trust

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Introduction](#2-introduction)
3. [Project Objectives](#3-project-objectives)
4. [Methodology and Results](#4-methodology-and-results)
5. [Social / Industry Relevance](#5-social--industry-relevance)
6. [Learning and Reflection](#6-learning-and-reflection)
7. [Conclusion and Future Scope](#7-conclusion-and-future-scope)

---

## 1. Executive Summary

A.C.E.S. (Autonomous Cyber-defence & Enforcement System) is a production-grade Zero Trust security platform built entirely in Python. It simulates a corporate financial portal — NorthStar Capital — defended by three simultaneous and independent detection layers:

| Detection Layer | Threat Caught | Automated Response |
|---|---|---|
| **PortTrap** — multi-port TCP honeypot | Port scans, reconnaissance probes | Instant IP ban (<5ms), session revocation |
| **HoneytokenWatcher** — filesystem monitor | Credential file access, insider threats | SOAR pipeline, SOC alert, ban |
| **BehaviorScorer** — IsolationForest ML | Anomalous click speed, request rates | SOC alert ≥ 0.50 · Auto-containment ≥ 0.85 |

All three layers feed into a unified SOC analyst dashboard that streams live threat events over WebSocket with sub-50ms latency. The system autonomously bans attacker IPs, revokes active sessions, and logs structured forensic records — while keeping the analyst in full control through a triage queue and manual override controls.

The anomaly detection model was trained on real benign network flows from the CIC-IoT-2023 dataset. Validated against live Kali Linux attack scenarios, the system correctly detected and contained every simulated threat.

---

## 2. Introduction

### Background and Context

Modern enterprise security has moved beyond perimeter defence. The Zero Trust model — "never trust, always verify" — treats every request as potentially hostile regardless of network location. Implementing this at the application layer requires:

- Continuous behavioural monitoring of every session
- Automated threat response that does not wait for human intervention
- Real-time analyst visibility into the full attack surface

Most small and medium organisations cannot afford commercial SIEM/SOAR platforms (Splunk, Palo Alto Cortex XSOAR) which cost upward of $100,000/year. A.C.E.S. demonstrates that the same core capabilities can be built with open-source components at zero licensing cost.

### Problem Statement

How can a system simultaneously detect external network attackers, filesystem-level intruders, and insider threats — and respond to all three automatically, in real time, without requiring a security engineer to watch a terminal?

### Scope

The project builds the complete detection and response stack:

- ML model training on real network flow data
- A scored HTTP financial portal (the target surface)
- Three-layer deception and detection infrastructure
- An event-driven SOAR pipeline
- A five-page live SOC analyst dashboard

Validated against real Kali Linux attack scenarios on a local network.

### Limitations

- The portal simulates financial transactions rather than implementing real banking logic
- AbuseIPDB reporting runs in offline-mock mode unless a live API key is configured
- Honeypot ports below 1024 require Administrator privileges on Windows

### Innovation Component

Most academic security projects implement one detection mechanism in isolation — either a honeypot or ML anomaly detection or a dashboard. A.C.E.S. integrates three orthogonal detection layers into a single real-time pipeline with a unified analyst interface — the same architecture used in commercial SIEM/SOAR products. The system is also unique in using a model trained on real network traffic and validating it against live attack tools.

---

## 3. Project Objectives

The project set out to achieve seven concrete objectives, each tied to a measurable success criterion. The first was to train an IsolationForest model on real benign network flows, with success defined as achieving clear score separation between benign traffic (0.05–0.25) and attack traffic (0.70–1.0). The second was to score every portal session in real time, with scores updating on every click within 100ms. The third was to auto-escalate sessions with score ≥ 0.85, banning the IP and revoking the session within 5ms. The fourth was to deploy multi-port TCP honeypots on ports 22, 445, and 3389 such that any TCP connect triggers an instant ban and SOC alert. The fifth was to deploy a filesystem honeytoken watched by a daemon, where any file access triggers the full SOAR pipeline. The sixth was to stream all threat events to the SOC dashboard over WebSocket with alerts appearing within 50ms of the trigger. The seventh was to provide five fully functional analytical views on the SOC dashboard, all role-gated to the SOC engineer account.

**Expected Deliverables:**

```
train_behavior_model.py     ← offline model trainer
run.py                      ← production server bootstrap
data/behavior_model.pkl     ← trained IsolationForest + RobustScaler
data/aces_production.db     ← SQLite event log database
src/
  zero_trust/scorer.py      ← BehaviorScorer
  zero_trust/models.py      ← data models
  soc_pipeline/soar_engine.py
  soc_pipeline/ws_dashboard.py
  soc_pipeline/event_hub.py
  deception/port_trap.py
  deception/token_watcher.py
  portal/financial_shell.py
  portal/static/soc.html    ← SOC dashboard
  portal/static/portal.html ← financial portal
  portal/static/index.html  ← landing / login
```

---

## 4. Methodology and Results

### Methods and Technology

Each component of the stack was chosen deliberately. Anomaly detection uses scikit-learn's IsolationForest, selected because it is unsupervised and requires no labelled attack data, while delivering O(n log n) inference speed. Feature scaling uses RobustScaler rather than StandardScaler because network flow data contains long-tailed distributions with extreme outliers, and RobustScaler's median/IQR normalisation handles these far better. The async HTTP server was built directly on Python asyncio with no web framework, allowing a single event loop to handle thousands of concurrent connections without thread overhead. WebSocket was implemented manually against RFC 6455 to avoid heavy framework dependencies and maintain full control over framing and keepalive. The database is SQLite in WAL mode, chosen for its in-process zero-latency reads and ability to handle concurrent reads while a single writer is active. Filesystem monitoring uses the watchdog library as a cross-platform wrapper over inotify and FSEvents. Frontend charts use Chart.js 4.4 for KDE density plots and live time-series streaming.

### Dataset

The model was trained on CIC-IoT-2023 — BenignTraffic.pcap.csv, sourced from the Canadian Institute for Cybersecurity. The dataset contains 362,361 rows of real benign network flow records with 29 feature columns including packet rates, inter-arrival times, TCP flag counts, protocol distributions, and packet size statistics. Preprocessing involved replacing ±Inf/NaN values, dropping affected rows, and applying RobustScaler normalisation. The full dataset was used for training with 10,000 held-out rows reserved for validation.

### ML Scoring Formula

```
raw_score  = IsolationForest.decision_function(X)   # negative = anomalous
clamped    = clip(raw_score, -0.5, +0.5)
score      = 0.5 - clamped                          # maps to [0, 1]

score = 0.0  →  deep inside benign cluster (perfectly normal)
score = 0.50 →  SOC alert threshold  (analyst review)
score = 0.85 →  SOAR auto-containment (ban + session revoke)
score = 1.0  →  maximum anomaly
```

### Validation Results

The system was validated against seven test scenarios, and every one produced the expected result. A full TCP connect port scan using `nmap -sT -p 3389` triggered an instant IP ban and PORT_TRAP alert on the SOC dashboard. A fast connect using `nc -z` banned the IP within 5ms. A directory brute-force probe hitting `/wp-admin` triggered an immediate honeytoken ban. Accessing `db_config.json` through the portal triggered the full SOAR pipeline and revoked the session. Normal portal browsing at a low click rate produced scores of 0.05–0.20 with no alert. Rapid button spam raised the score above 0.50 and triggered a SOC alert. A post-ban HTTP request from the Kali VM returned the 403 quarantine page.

### Dashboard Pages

**Page 1 — Active Logs & Details** Live terminal-style event stream over WebSocket. Every PORT_TRAP, HONEYTOKEN_ACCESS, and AI_ANOMALY event appears within 50ms of firing. Bottom panel shows the Top 5 most volatile IPs by anomaly score.

**Page 2 — Live Triage Queue** Table of all security events with unread badge counter. Clicking a row reveals the full event detail panel (IP, username, role, trigger, score, timestamp) and provides one-click analyst actions: Investigate, Manual Ban, Remove Ban, Report to AbuseIPDB.

**Page 3 — Deception & Honeytokens** Shows live honeytoken file content, active honeypot port status, honeytoken trip history, SOAR mode toggle (Monitor-Only vs Enforce), and a live honeyport management control for changing trap ports without restarting the server.

**Page 4 — Anomaly Score Distribution** KDE density plot showing green benign traffic curve (peaks at 0.10–0.15) vs red attack traffic curve (peaks at 0.80–0.95), scored by the production IsolationForest against real CSV rows. Two dashed threshold lines at 0.50 and 0.85.

**Page 5 — Baseline Timeline** Live time-series chart that polls the scorer every 5 seconds and plots anomaly score vs the 0.50 baseline threshold. Score line turns red when crossing into the anomaly zone. Slider controls adjust request rate and click interval to simulate different traffic profiles in real time.

**GitHub Link:** https://github.com/sure-trust/RAKESH-S-g15-cs

---

## 5. Social / Industry Relevance

### Industry Relevance

Zero Trust architecture is the current global standard for enterprise security — mandated by the US Executive Order on Cybersecurity (May 2021) and adopted by Google (BeyondCorp), Microsoft (Azure AD Conditional Access), and Cloudflare (Zero Trust Network Access). A.C.E.S. implements the same core capabilities as commercial platforms: its EventHub and SOC Dashboard mirror the role of Splunk SIEM, its SOAREngine mirrors Palo Alto Cortex XSOAR, its BehaviorScorer mirrors CrowdStrike Falcon's behavioural detection, and its PortTrap and HoneytokenWatcher mirror Attivo Networks honeypot infrastructure.

### Social Relevance

Cybercrime costs the global economy over $8 trillion annually (Cybersecurity Ventures, 2023). Small and medium businesses — which disproportionately serve rural and underserved communities — are the most frequent targets because they cannot afford enterprise security tools.

A.C.E.S. demonstrates that production-quality threat detection can be built entirely with open-source components at zero licensing cost, making it accessible to hospitals, NGOs, local government bodies, and educational institutions that operate without security budgets.

---

## 6. Learning and Reflection

### Technical Learnings

**Machine Learning**
- How IsolationForest works: isolation path length as anomaly signal; why shorter average path = more anomalous
- Why `contamination=0.02` (2%) gives a tighter boundary than the default 0.10
- Why RobustScaler (median/IQR) outperforms StandardScaler (mean/std) for network flow data with long-tailed distributions
- The difference between unsupervised anomaly detection and supervised classification — and why unsupervised is the only option when there is no labelled attack data

**Async Python**
- How the asyncio event loop works: cooperative multitasking, why `await` does not block, how `create_task` enables concurrency
- The difference between `asyncio.Queue` fan-out and a single shared queue — and why fan-out is required for independent consumers at different speeds
- How to bridge OS-level threads (watchdog file monitor) into the async event loop using `call_soon_threadsafe`

**Network Security**
- Why Nmap's default `-sS` SYN scan does not trigger `asyncio.start_server` but `-sT` full connect does — and how this gap affects real-world honeypot effectiveness
- How TCP banner responses reveal service versions to attackers — and why sending zero bytes is the correct honeypot design
- What TTL values, TCP flag patterns, and IAT distributions reveal about traffic type

**System Design**
- Why the ban is written to SQLite before SOAR fires — to prevent a race window where the next HTTP request arrives before the async task executes
- Why WAL (Write-Ahead Logging) mode allows concurrent SQLite readers without blocking the writer
- The role of idempotency in security operations — why `ban_ip()` uses `INSERT OR REPLACE` so repeated calls are safe

### Overall Experience

Building A.C.E.S. from scratch gave me an end-to-end understanding of how production security systems are actually constructed — not just the theory but the exact code paths: from a TCP packet arriving on a honeypot port, to an alert appearing on a SOC analyst's screen 50ms later, to an IP being permanently blocked in the database.

The most valuable insight was that every architectural decision in a security system has a direct threat model consequence. Why does the EventHub use per-subscriber queues? Because if the analytics consumer blocks, it must not delay the WebSocket broadcast that the analyst is watching. Why is the honeytoken file pre-populated with realistic-looking fake credentials? Because an attacker who opens an empty file knows immediately it is a trap.

---

## 7. Conclusion and Future Scope

### Recap of Objectives and Achievements

Every objective set out at the start of the project was completed. The IsolationForest model was trained on 362,000 real benign network flows and achieves clear score separation between normal and attack traffic. Real-time session scoring updates on every click within 100ms. Auto-containment fires within 5ms of a score exceeding 0.85. Multi-port TCP honeypots on ports 22, 445, and 3389 correctly detect and ban port scanners. The filesystem honeytoken watcher detects any credential file access. The SOC dashboard streams live events with sub-50ms WebSocket latency across all five analytical pages. Every test scenario run from the Kali Linux VM was detected and contained as expected.

### Future Scope

Several enhancements are planned for future iterations of the system. Adding HTTPS/TLS via Let's Encrypt would prevent credential interception in production deployment. Replacing SQLite with PostgreSQL would support multi-analyst concurrent access and long-term log retention. Training a supervised classification model on CIC-IDS-2018 labelled attack data would add a complementary detection layer alongside the unsupervised baseline. Adding PCAP capture on honeypot ports would provide full packet-level forensic evidence for incident response. Enabling live AbuseIPDB reporting would allow automated community threat intelligence sharing. Packaging the system as a Docker container with docker-compose would enable one-command reproducible deployment. Adding email and SMS alerting would notify analysts when critical events fire with no dashboard connection open.
