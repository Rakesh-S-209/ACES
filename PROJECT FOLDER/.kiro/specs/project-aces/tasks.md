# Implementation Plan: Project A.C.E.S.

## Overview

Project A.C.E.S. implementation is organized into six phases: (1) project scaffolding and data models, (2) backend core components (EventHub, BehaviorScorer, Gateway, SOAR, TokenWatcher, PortTrap, WebSocket handler), (3) FastAPI application wiring and startup lifecycle, (4) frontend React SPAs (Corporate Portal and SOC Dashboard), (5) property-based and unit/integration tests, and (6) security hardening. All tasks are ordered by dependency and reference specific requirements.

## Tasks

- [ ] 1. Initialize repository structure and data models
  - [ ] 1.1 Create project directory structure and configuration files
    - Create all backend directories: `src/zero_trust/`, `src/deception/`, `src/soc_pipeline/`
    - Create data directories: `data/honey_tokens/`, `data/`
    - Create frontend directories: `web_apps/corporate_portal/`, `web_apps/soc_dashboard/`
    - Add `__init__.py` files to all `src/` packages
    - Create `requirements.txt` with pinned versions for: `fastapi>=0.110.0`, `uvicorn[standard]>=0.29.0`, `watchdog>=4.0.0`, `pandas>=2.2.0`, `scikit-learn>=1.4.0`, `aiohttp>=3.9.0`, `websockets>=12.0`, `PyYAML>=6.0.1`, `python-dotenv>=1.0.0`, `pydantic>=2.0.0`, `hypothesis`, `pytest`, `pytest-asyncio`, `httpx`
    - Create `.env.example` with placeholder values for `ABUSEIPDB_API_KEY`, `SOC_MASTER_SECRET`, and `FASTAPI_ENV`
    - Create `.gitignore` excluding `.env`, `__pycache__/`, and `*.pyc`
    - Create `data/honey_tokens/db_config.json` with realistic-looking but invalid database credentials
    - Create `data/malicious_ips_db.json` with pre-populated known malicious IPs in format `{"ip": {"abuse_score": N, "country": "XX", "reports": N}}`
    - _Requirements: 13.4, 13.5, 5.4, 5.5, 6.1_

  - [ ] 1.2 Implement core enumeration types and data models
    - Implement `SessionStatus` enum with members `ACTIVE`, `REVOKED`, `EXPIRED` in `src/zero_trust/models.py`
    - Implement `AlertType` enum with members `AI_ANOMALY`, `HONEYTOKEN_ACCESS`, `PORT_TRAP`
    - Implement `PolicyAction` enum with members `ALLOW`, `BLOCK`, `REVOKE`
    - Implement `TelemetryVector` dataclass with fields `click_speed_intervals`, `page_path_weights`, `sequence_transitions`, `session_duration_ms`, `request_rate_per_sec`; include `to_feature_array()` method that returns a flat finite-float list and raises `ValueError` if any NaN/Infinity result
    - Implement `SessionRecord` dataclass with fields `session_id`, `ip_address`, `role`, `anomaly_score`, `status`, `created_at_ms`, `revoked_at_ms`; implement `revocation_delta_ms` computed property returning `revoked_at_ms - created_at_ms` for REVOKED records and `None` otherwise
    - Implement `AlertEvent` dataclass with required fields `alert_type`, `source_ip`, `timestamp_ms` and optional fields `session_id`, `anomaly_score`, `affected_path`, `port`, `abuse_score`, `revocation_delta_ms` (all defaulting to `None`); implement `to_json()` that serializes all non-None fields with `alert_type` as its string enum value
    - Implement `IPReputationReport` dataclass with fields `ip_address`, `abuse_confidence_score`, `country_code`, `total_reports`, `is_whitelisted`, `source`
    - Implement `GatewayDecision` dataclass with fields `action`, `session_id`, `anomaly_score`, `reason`
    - Implement `SOARResult` dataclass with fields `success`, `delta_ms`
    - _Requirements: 4.5, 4.6, 4.7, 4.8, 4.9, 3.7, 3.8, 12.1, 12.2, 12.6, 12.7_


- [ ] 2. Implement backend core components
  - [ ] 2.1 Implement EventHub (`src/soc_pipeline/event_hub.py`)
    - Create a module-level singleton `asyncio.Queue` instance
    - Implement `publish(event: AlertEvent) -> None` as an async method that enqueues events without blocking
    - Implement `subscribe() -> AsyncIterator[AlertEvent]` as an async generator yielding events to subscribers
    - Implement `get_queue() -> asyncio.Queue` to expose the underlying queue for `call_soon_threadsafe` bridging from OS threads
    - Implement fan-out delivery with delivery count tracking per event (increment by number of active subscribers reached)
    - Ensure subscribers receive events in the exact order they were published
    - _Requirements: 8.1, 8.2, 8.3, 8.5, 8.6_

  - [ ]* 2.2 Write property tests for EventHub
    - **Property 20: EventHub Delivers Events to All Active Subscribers** — for any N subscribers, all N receive each published event
    - **Property 21: EventHub Preserves Event Ordering** — all subscribers receive events in publication order
    - **Property 22: EventHub Tolerates Subscriber Disconnection** — remaining subscribers still receive event after one disconnects mid-fan-out
    - **Validates: Requirements 8.2, 8.3, 8.4, 8.6**

  - [ ] 2.3 Implement BehaviorScorer (`src/zero_trust/scorer.py`)
    - Implement `BehaviorScorer` with `__init__(n_estimators: int = 100, contamination: float = 0.05)` that stores configurable parameters
    - Implement `fit(baseline_vectors: list[TelemetryVector]) -> None` that trains the `IsolationForest` model on a feature matrix
    - Implement `predict(telemetry: TelemetryVector) -> float`: call `telemetry.to_feature_array()`, raise `ValueError` if array contains NaN or Infinity, run `decision_function`, clamp raw to `[-0.5, 0.5]`, return `(0.5 - clamped) / 1.0`
    - Ensure `predict()` raises `sklearn.exceptions.NotFittedError` when called before `fit()`
    - Ensure `predict()` propagates any exception raised during `fit()` without converting to `NotFittedError`
    - _Requirements: 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

  - [ ]* 2.4 Write property tests for BehaviorScorer
    - **Property 1: Anomaly Scores Are Always Bounded** — for any valid TelemetryVector, `predict()` returns a float in [0.0, 1.0]
    - **Property 5: Score Normalization Formula Is Correct** — for any raw float, normalized result equals `(0.5 - max(-0.5, min(0.5, raw))) / 1.0` and lands in [0.0, 1.0]
    - **Property 6: Score Determinism** — same TelemetryVector produces same score across multiple calls on same fitted model
    - **Validates: Requirements 2.2, 2.3, 2.7**

  - [ ] 2.5 Implement TelemetryVector validation logic in `src/zero_trust/validation.py`
    - Validate `click_speed_intervals`: non-empty list, at most 1000 elements, all values ≥ 0.0
    - Validate `page_path_weights`: non-empty collection, all values in [0.0, 1.0]
    - Validate `sequence_transitions`: all elements are integers in [1, 999999]
    - Validate `session_duration_ms`: non-negative float, max 86400000
    - Validate `request_rate_per_sec`: non-negative float, max 10000.0
    - Return a field-specific error description for any validation failure; do not proceed to ML scoring on any failure
    - Verify `to_feature_array()` output contains no NaN or Infinity; treat any such value as a validation failure
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_

  - [ ]* 2.6 Write property tests for TelemetryVector validation
    - **Property 7: TelemetryVector Validation Rejects Invalid Fields** — for any vector with a negative `click_speed_intervals` value, out-of-range `page_path_weights`, negative `session_duration_ms`, or negative `request_rate_per_sec`, Gateway rejects without invoking ML
    - **Property 8: to_feature_array Produces Finite Numeric Arrays** — for any fully populated TelemetryVector with finite fields, `to_feature_array()` returns a non-empty all-finite list
    - **Validates: Requirements 3.1, 3.2, 3.4, 3.5, 3.6, 3.7**


  - [ ] 2.7 Implement Zero Trust Gateway (`src/zero_trust/gateway.py`)
    - Implement `process_request(request, sessions, blacklist) -> GatewayDecision` following the algorithm: (1) check `blacklist` → return `BLOCK` without invoking BehaviorScorer or writing session; (2) validate and vectorize telemetry → return HTTP 422 on any failure; (3) call `BehaviorScorer.predict()`; (4) if score > 0.75 invoke `SOAR_Engine.trigger_response()` and return `REVOKE` (include failure indicator in reason if SOAR fails, but still return REVOKE); (5) if score ≤ 0.75 upsert `SessionRecord` into `sessions` with `status=ACTIVE` and return `ALLOW` (return error reason and do NOT return ALLOW if upsert fails)
    - Attach the normalized AnomalyScore to every `GatewayDecision` regardless of PolicyAction
    - Return HTTP 503 if PERIMETER_BLACKLIST lookup itself raises an error
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11_

  - [ ]* 2.8 Write property tests for Zero Trust Gateway
    - **Property 2: Blacklisted IPs Are Always Blocked** — for any IP in PERIMETER_BLACKLIST, `process_request()` returns `action=BLOCK` without creating a session record
    - **Property 3: Score Threshold Determines Policy Action Exclusively** — for any non-blacklisted IP, score > 0.75 produces REVOKE; score ≤ 0.75 produces ALLOW
    - **Property 4: Anomaly Score Is Always Attached to Every Decision** — every GatewayDecision has a non-None AnomalyScore regardless of PolicyAction
    - **Validates: Requirements 1.1, 1.2, 1.4, 1.6, 1.8**

  - [ ] 2.9 Implement SOAR Engine (`src/soc_pipeline/soar.py`)
    - Implement `lookup_ip_reputation(ip: str) -> IPReputationReport` using `aiohttp` with `aiohttp.ClientTimeout(total=5.0)` and `ABUSEIPDB_API_KEY` from `os.environ`; on success, construct `IPReputationReport` with `source="abuseipdb"`; catch `aiohttp.ClientError` and `asyncio.TimeoutError` and fall through to offline fallback
    - Implement `load_offline_fallback(ip: str) -> IPReputationReport`: load `data/malicious_ips_db.json`; on `FileNotFoundError` or `json.JSONDecodeError` return an `IPReputationReport` with `abuse_confidence_score=0` and `source="offline_fallback_error"`; on success return report with `source="offline_fallback"`
    - Ensure `lookup_ip_reputation()` never raises for any string input
    - Implement `trigger_response(ip, session_id, score, sessions, blacklist, event_hub) -> SOARResult`: call `lookup_ip_reputation()` → add `ip` to `blacklist` → set `sessions[session_id].status = REVOKED` and record `revoked_at_ms` → compute `revocation_delta_ms` → publish `AI_ANOMALY` `AlertEvent` with `source_ip`, `anomaly_score`, `abuse_score`, `session_id`, `revocation_delta_ms`
    - If blacklisting or revocation fails, log the failure and still publish an `AlertEvent` with available data; do not suppress alert
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 5.10_

  - [ ]* 2.10 Write property tests for SOAR Engine
    - **Property 11: SOAR Always Blacklists the Attacker IP** — for any IP passed to `trigger_response()`, IP is in PERIMETER_BLACKLIST after completion
    - **Property 12: SOAR Always Revokes the Triggering Session** — for any session ID passed to `trigger_response()`, session has `status=REVOKED` and non-None `revoked_at_ms` after completion
    - **Property 13: SOAR Always Publishes an AI_ANOMALY Alert** — for any `trigger_response()` invocation, exactly one `AI_ANOMALY` AlertEvent is published
    - **Property 14: IP Reputation Lookup Never Raises** — for any string input (including malformed or empty), `lookup_ip_reputation()` returns a valid `IPReputationReport` without raising
    - **Validates: Requirements 5.6, 5.7, 5.8, 5.10**

  - [ ] 2.11 Implement TokenWatcher (`src/deception/token_watcher.py`)
    - Implement `HoneytokenWatcher` using the `watchdog` library monitoring the `data/honey_tokens/` directory
    - Filter events to `db_config.json` filename only; return immediately from `on_any_event()` for any directory event (`event.is_directory` check)
    - Implement `on_any_event(event)`: create a `HONEYTOKEN_ACCESS` `AlertEvent` with `source_ip="local"`, `affected_path=event.src_path`, and `timestamp_ms=time.time()*1000`; bridge into asyncio using `self._loop.call_soon_threadsafe(self._event_hub.get_queue().put_nowait, alert)`
    - Do NOT add any IP address to PERIMETER_BLACKLIST (filesystem events carry no network IP address)
    - Run the watchdog observer as a background daemon thread (`daemon=True`)
    - Implement `start()` method that schedules the observer and calls `observer.start()`
    - Implement `stop()` method that calls `observer.stop()` and `observer.join()`
    - Handle startup case where `data/honey_tokens/db_config.json` does not yet exist: monitor the parent directory and treat the newly created file as HoneytokenFile upon creation
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8_

  - [ ]* 2.12 Write property tests for TokenWatcher
    - **Property 15: TokenWatcher Publishes Exactly One Alert Per File Event** — for any filesystem event on HoneytokenFile, exactly one `HONEYTOKEN_ACCESS` AlertEvent is enqueued with the affected path and millisecond timestamp
    - **Property 16: TokenWatcher Ignores Directory Events** — for any directory event, no AlertEvent is published
    - **Property 17: TokenWatcher Bridges Events Thread-Safely into asyncio** — AlertEvent is enqueued via `call_soon_threadsafe`, not direct `put()`
    - **Validates: Requirements 6.3, 6.4, 6.6**


  - [ ] 2.13 Implement PortTrap (`src/deception/port_trap.py`)
    - Implement async TCP server using `asyncio.start_server` bound to port 3389
    - Implement `handle_connection(reader, writer)`: extract source IP from `writer.get_extra_info("peername")`; add source IP to `PERIMETER_BLACKLIST`; publish a `PORT_TRAP` `AlertEvent` to `EventHub` with `source_ip`, `port=3389`, and `timestamp_ms`; call `writer.close()` and `await writer.wait_closed()` within 100ms; send zero bytes to the client
    - Wrap each connection in an independent `asyncio.create_task()` so one slow connection cannot block subsequent detections
    - Catch `OSError` on `asyncio.start_server` bind failure: log a startup warning with the port number and return without raising, allowing other subsystems to continue
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [ ]* 2.14 Write property tests for PortTrap
    - **Property 18: PortTrap Sends Zero Bytes on Every Connection** — for any inbound TCP connection, PortTrap transmits zero bytes before closing
    - **Property 19: PortTrap Always Publishes a PORT_TRAP Alert** — for any inbound TCP connection, exactly one `PORT_TRAP` AlertEvent with correct source IP, port 3389, and timestamp is published
    - **Validates: Requirements 7.3, 7.4**

  - [ ] 2.15 Implement WebSocket Stream Handler (`src/soc_pipeline/ws_handler.py`)
    - Implement FastAPI WebSocket endpoint at `/api/soc/stream` accepting a `token` query parameter
    - Before completing the WebSocket upgrade, check the client origin IP; reject with HTTP 403 if not `127.0.0.1` or `::1`
    - Validate `token == os.environ["SOC_MASTER_SECRET"]`; reject with HTTP 403 before upgrade if mismatch
    - On successful upgrade, register the WebSocket as an EventHub subscriber immediately
    - Implement broadcast loop: for each event from `EventHub.subscribe()`, call `await ws.send_json(event.to_json())`; raise (do not swallow) any serialization error from `to_json()` before transmitting
    - On `WebSocketDisconnect`, remove the client from the EventHub subscriber list without crashing; continue serving remaining clients
    - Events must be relayed within 500ms of publication to the EventHub
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 15.4_

  - [ ]* 2.16 Write property tests for SOCStreamHandler and AlertEvent serialization
    - **Property 23: SOCStreamHandler Rejects Unauthorized Connections** — for any token not matching `SOC_MASTER_SECRET`, connection is rejected before WebSocket upgrade
    - **Property 24: AlertEvent Serialization Round-Trip** — for any valid AlertEvent, `to_json()` then reconstruct produces an equivalent object with all non-None fields preserved
    - **Property 25: AlertEvent Required Fields Are Always Present** — for any AlertEvent, `alert_type`, `source_ip`, `timestamp_ms` are non-None in serialized output
    - **Property 26: AI_ANOMALY Events Contain Required Enrichment Fields** — for any `AI_ANOMALY` AlertEvent from SOAR, `session_id`, `anomaly_score`, `abuse_score`, `revocation_delta_ms` are all non-None
    - **Validates: Requirements 9.2, 9.3, 12.1, 12.3, 12.6, 12.7**

- [ ] 3. Implement FastAPI application entry point and startup lifecycle
  - [ ] 3.1 Create FastAPI app and startup/shutdown lifecycle handlers (`src/main.py`)
    - Instantiate the FastAPI application
    - Implement `@app.on_event("startup")` handler executing initialization in strict order: (1) read and validate `ABUSEIPDB_API_KEY`, `SOC_MASTER_SECRET`, `FASTAPI_ENV` from `os.environ`; raise `EnvironmentError` naming any missing/empty variable; (2) initialize `EventHub` singleton; (3) generate ≥100 synthetic baseline `TelemetryVector` samples and call `BehaviorScorer.fit()` — do not register any route handlers before this completes; (4) instantiate and `start()` the `HoneytokenWatcher` daemon; (5) create `asyncio.Task` for `PortTrap.start_server()` (skip with log warning if port 3389 is in use); (6) include route handlers via `app.include_router()`
    - Implement `@app.on_event("shutdown")` handler that calls `watcher.stop()` and joins the daemon thread
    - Configure FastAPI CORS middleware with `allow_origins` restricted to the CorporatePortal's origin; development: allow `localhost` CorporatePortal origin; production: allow only the production portal hostname
    - _Requirements: 13.6, 13.7, 13.8, 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 15.1_

  - [ ] 3.2 Implement `POST /api/auth` route handler
    - Define an `AuthPayload` Pydantic model with `role` and all TelemetryVector fields; Pydantic validation handles HTTP 422 for missing or malformed fields automatically
    - Implement the route: delegate to `gateway.process_request(payload, ACTIVE_SESSIONS, PERIMETER_BLACKLIST)`; return HTTP 200 with session token and role on `ALLOW`; return HTTP 403 with reason `"blacklisted_ip"` on `BLOCK`; return HTTP 403 with reason `"anomalous_behavior"` on `REVOKE`; return HTTP 503 on PERIMETER_BLACKLIST lookup error
    - _Requirements: 1.1–1.11, 3.1–3.8_

- [ ] 4. Implement frontend applications
  - [ ] 4.1 Scaffold and implement Corporate Portal React SPA (`web_apps/corporate_portal/`)
    - Initialize Vite + React + TypeScript project with TailwindCSS
    - Implement login page UI with `username`, `password`, and `role` selector (Admin/Engineer/Guest)
    - Implement telemetry collection hooks: capture `click_speed_intervals` from click-event timing differences, `page_path_weights` from navigation frequency map, `sequence_transitions` from ordered page visit IDs, `session_duration_ms` from session start time, `request_rate_per_sec` from request count divided by elapsed seconds
    - On form submit, POST to `/api/auth` with credentials and fully populated `TelemetryVector` payload
    - On HTTP 403 response: display a generic access-denied message containing no references to honeypots, deception, monitoring, security analysis, system identifiers, component names, or backend error details
    - On HTTP 422, HTTP 5xx, or network failure: display a generic error message with no backend detail exposure
    - Ensure no WebSocket endpoints, alert data, session records, blacklist entries, backend route paths, or internal system details are accessible or leaked from this SPA
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_


  - [ ] 4.2 Scaffold and implement SOC Dashboard React SPA (`web_apps/soc_dashboard/`)
    - Initialize Vite + React + TypeScript project with TailwindCSS and Recharts
    - Implement `useSOCStream(masterSecret: string)` hook: open `WebSocket` to `ws://localhost:8000/api/soc/stream?token={masterSecret}`; on `ws.onmessage`, parse the JSON payload as `AlertEvent` and prepend to alerts state within the same render cycle
    - On `ws.onclose`, schedule exactly one reconnection attempt via `setTimeout(..., 2000)`; do not schedule further retries until the current attempt either succeeds or fails
    - Implement alert feed display: show `alert_type`, `source_ip`, `timestamp_ms` for all alerts; additionally show `anomaly_score` and `revocation_delta_ms` for `AI_ANOMALY` events; show `affected_path` for `HONEYTOKEN_ACCESS` events
    - Implement PERIMETER_BLACKLIST grid component that updates within the current render cycle when the backend pushes a blacklist-change event
    - Configure Vite dev server with `host: '127.0.0.1'` in `vite.config.ts`; production serving must also bind only to `127.0.0.1`
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

  - [ ]* 4.3 Write unit tests for SOC Dashboard rendering
    - **Property 27: SOCDashboard Renders All Required Alert Fields** — for any AlertEvent received, rendered output contains `alert_type`, `source_ip`, `timestamp_ms`; additionally `anomaly_score` and `revocation_delta_ms` for `AI_ANOMALY`; `affected_path` for `HONEYTOKEN_ACCESS`
    - Test reconnection logic: simulate `ws.onclose` and assert exactly one `setTimeout` call with 2000ms delay; assert no additional retries are scheduled while one is pending
    - **Validates: Requirements 11.4, 11.5**

- [ ] 5. Checkpoint — Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement SessionRecord property tests and integration tests
  - [ ] 6.1 Write property tests for SessionRecord and in-memory state
    - **Property 9: SessionRecord Required Fields Are Always Present** — for any newly constructed SessionRecord, all of `session_id`, `ip_address`, `role`, `anomaly_score`, `status`, `created_at_ms` are non-None and `status=ACTIVE`
    - **Property 10: Revocation Delta Is Correctly Computed** — for any revoked SessionRecord, `revocation_delta_ms == revoked_at_ms - created_at_ms` and is non-negative; for non-revoked records, returns `None`
    - **Validates: Requirements 4.5, 4.7, 4.8, 4.9**

  - [ ] 6.2 Write integration tests for the full auth and SOAR pipeline
    - Test normal auth flow: POST valid low-anomaly telemetry → assert HTTP 200, session created in `ACTIVE_SESSIONS`, `status=ACTIVE`
    - Test high-anomaly flow: POST high-anomaly telemetry → assert HTTP 403 with `"anomalous_behavior"`, session in `ACTIVE_SESSIONS` has `status=REVOKED`, source IP in `PERIMETER_BLACKLIST`, one `AI_ANOMALY` event in `EventHub`
    - Test blacklisted IP: add IP to `PERIMETER_BLACKLIST`, POST any request → assert HTTP 403 with `"blacklisted_ip"`, no BehaviorScorer call (mock verify), no new session record
    - Test AbuseIPDB failure: mock `aiohttp` to raise `asyncio.TimeoutError` → assert `IPReputationReport.source == "offline_fallback"` and pipeline still completes (IP blacklisted, session revoked, alert published)
    - Test missing offline fallback: mock both `aiohttp` timeout and missing `data/malicious_ips_db.json` → assert `IPReputationReport.source == "offline_fallback_error"` and pipeline still completes
    - Test WebSocket stream: connect test client to `/api/soc/stream` with valid token → simulate honeytoken file event → assert `HONEYTOKEN_ACCESS` message received within 500ms
    - Test WebSocket auth rejection: connect with wrong token → assert HTTP 403 before upgrade
    - _Requirements: 1.1, 1.4, 2.5, 5.4–5.9, 6.3, 7.3–7.4, 9.2–9.5, 13.6, 13.7_

- [ ] 7. Implement environment variable validation and security hardening
  - [ ] 7.1 Implement environment variable loading and startup validation (`src/config.py`)
    - Load `.env` via `python-dotenv` in development environments
    - Read `ABUSEIPDB_API_KEY`, `SOC_MASTER_SECRET`, `FASTAPI_ENV` exclusively from `os.environ[...]` (not `os.getenv`); raise `EnvironmentError` with the name of the missing/empty variable at startup if any are absent
    - Ensure no request-handling routes are registered if `EnvironmentError` is raised
    - _Requirements: 13.1, 13.2, 13.3, 13.6, 13.7, 13.8_

  - [ ] 7.2 Implement CORS and network binding configuration
    - Configure FastAPI CORS middleware: development allows `localhost` CorporatePortal origin; production allows only the production portal hostname; all other origins are rejected before reaching route handlers
    - Verify `uvicorn` bind address for backend is `0.0.0.0` for corporate portal exposure and `127.0.0.1` exclusively for SOC Dashboard server
    - Confirm `web_apps/soc_dashboard/vite.config.ts` sets `server.host: '127.0.0.1'`
    - Confirm `SOCStreamHandler` rejects non-localhost source IPs before WebSocket upgrade
    - In production, configure HTTPS redirect or require TLS termination at reverse proxy for the CorporatePortal → backend path
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

- [ ] 8. Final checkpoint — Ensure all tests pass, ask the user if questions arise.


## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP, but are strongly recommended for correctness verification.
- All property-based tests use the `hypothesis` library with a minimum of 100 iterations per property.
- Secrets must be read exclusively from environment variables via `os.environ[...]` — never `os.getenv`, hardcoded, or logged.
- The BehaviorScorer **must** be fitted before any route handler is registered (enforced by startup order in task 3.1).
- The TokenWatcher **must NOT** add any IP address to PERIMETER_BLACKLIST — filesystem events carry no network IP (per Requirements 6.5).
- The SOC Dashboard dev server and production server **must** bind exclusively to `127.0.0.1` (not `0.0.0.0`).
- The PortTrap must handle each connection as an independent `asyncio.create_task()` to prevent one slow connection from blocking others.
- Property tests are placed close to the implementation tasks they validate to catch errors early in the implementation sequence.
- Each property test task explicitly references the property number from the design document's "Correctness Properties" section.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["2.1", "2.3", "2.5"] },
    { "id": 2, "tasks": ["2.2", "2.4", "2.6", "2.7", "2.11", "2.13"] },
    { "id": 3, "tasks": ["2.8", "2.9", "2.12", "2.14", "2.15"] },
    { "id": 4, "tasks": ["2.10", "2.16", "3.1"] },
    { "id": 5, "tasks": ["3.2", "4.1", "4.2"] },
    { "id": 6, "tasks": ["4.3", "6.1", "7.1"] },
    { "id": 7, "tasks": ["6.2", "7.2"] }
  ]
}
```
