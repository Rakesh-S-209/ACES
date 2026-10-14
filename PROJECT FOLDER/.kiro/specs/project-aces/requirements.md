# Requirements Document

## Introduction

Project A.C.E.S. (Automated Cybersecurity & Deception System) is a full-stack, production-ready cybersecurity deception and monitoring platform. It exposes a convincing public-facing corporate decoy portal to lure and fingerprint attackers, while a local-only SOC console gives security analysts real-time telemetry, automated threat response, and live blacklist management. All operational state is stored exclusively in RAM, ensuring low-latency response and forensic deniability. The system integrates an AI-powered Zero Trust gateway, passive deception daemons, a WebSocket-based event streaming pipeline, and a SOAR automation engine with external threat intelligence enrichment.

---

## Glossary

- **Gateway**: The Zero Trust AI gateway component (`src/zero_trust/gateway.py`) that is the single entry point for all inbound requests.
- **BehaviorScorer**: The Isolation Forest ML model component embedded in the Gateway that computes normalized anomaly scores from behavioral telemetry.
- **TelemetryVector**: A structured data object containing click speed intervals, page path weights, sequence transitions, session duration, and request rate captured from a client session.
- **AnomalyScore**: A normalized floating-point value in [0.0, 1.0] output by the BehaviorScorer, where values closer to 1.0 indicate higher anomaly likelihood.
- **ACTIVE_SESSIONS**: The in-memory dictionary keyed by session ID that stores all `SessionRecord` objects for the current runtime.
- **PERIMETER_BLACKLIST**: The in-memory set of IP address strings that are permanently denied by the Gateway for the duration of the current runtime.
- **SessionRecord**: A data object representing a user session with fields for session ID, IP address, role, anomaly score, status, and timestamps.
- **SessionStatus**: An enumeration of session states: `ACTIVE`, `REVOKED`, or `EXPIRED`.
- **AlertEvent**: A structured event object representing a security alert with a type, source IP, timestamp, and optional enrichment fields.
- **AlertType**: An enumeration of alert categories: `AI_ANOMALY`, `HONEYTOKEN_ACCESS`, or `PORT_TRAP`.
- **EventHub**: The singleton asyncio.Queue-backed publish/subscribe bus that decouples event producers from WebSocket consumers.
- **SOAR_Engine**: The SOAR automation component (`src/soc_pipeline/soar.py`) that orchestrates threat response, IP reputation lookup, and alert publication.
- **TokenWatcher**: The honeytoken filesystem monitor daemon (`src/deception/token_watcher.py`) that watches the decoy credential file for any access event.
- **PortTrap**: The TCP decoy server (`src/deception/port_trap.py`) bound to port 3389 that logs and immediately drops inbound connections.
- **SOCStreamHandler**: The FastAPI WebSocket endpoint (`src/soc_pipeline/ws_handler.py`) at `/api/soc/stream` that fans out alert events to SOC dashboard clients.
- **CorporatePortal**: The public-facing decoy React SPA (`web_apps/corporate_portal/`) that presents a convincing corporate login interface to attackers.
- **SOCDashboard**: The local-only private React SPA (`web_apps/soc_dashboard/`) that displays real-time alerts, session state, and blacklist management to analysts.
- **IPReputationReport**: A data object containing AbuseIPDB enrichment data for a given IP address, including an integer abuse confidence score in [0, 100], country code, and data source identifier.
- **GatewayDecision**: A data object returned by the Gateway encoding the policy action (`ALLOW`, `BLOCK`, or `REVOKE`), anomaly score, and reason.
- **ABUSEIPDB_API_KEY**: An environment variable holding the API key for the AbuseIPDB threat intelligence service.
- **SOC_MASTER_SECRET**: An environment variable holding the authentication token required to establish a WebSocket connection to the SOC stream.
- **HoneytokenFile**: The decoy credential file at `data/honey_tokens/db_config.json` that serves as a bait artifact for intruders.
- **OfflineFallbackDB**: The pre-populated local threat intelligence file at `data/malicious_ips_db.json` used when AbuseIPDB is unreachable.
- **PolicyAction**: An enumeration of Gateway enforcement outcomes: `ALLOW`, `BLOCK`, or `REVOKE`.

---

## Requirements

### Requirement 1: Zero Trust Gateway Request Processing

**User Story:** As a security operator, I want every inbound request to be evaluated by the Zero Trust Gateway before access is granted, so that no request bypasses behavioral analysis and blacklist enforcement.

#### Acceptance Criteria

1. WHEN a request arrives at the Gateway, THE Gateway SHALL check the source IP against PERIMETER_BLACKLIST before performing any other processing.
2. WHEN the source IP of a request is present in PERIMETER_BLACKLIST, THE Gateway SHALL return a `GatewayDecision` with `action=BLOCK` and SHALL NOT invoke the BehaviorScorer or create a session record.
3. WHEN the source IP is not in PERIMETER_BLACKLIST, THE Gateway SHALL extract and vectorize the telemetry payload into a TelemetryVector and invoke the BehaviorScorer.
4. WHEN the BehaviorScorer returns an AnomalyScore strictly greater than 0.75, THE Gateway SHALL invoke the SOAR_Engine and return a `GatewayDecision` with `action=REVOKE`.
5. WHEN the SOAR_Engine invocation fails after an AnomalyScore greater than 0.75 is detected, THE Gateway SHALL still return a `GatewayDecision` with `action=REVOKE` and SHALL include a failure indicator in the reason field of the decision.
6. WHEN the BehaviorScorer returns an AnomalyScore of 0.75 or less, THE Gateway SHALL upsert a SessionRecord into ACTIVE_SESSIONS with `status=ACTIVE` and return a `GatewayDecision` with `action=ALLOW`.
7. IF the ACTIVE_SESSIONS upsert fails after a non-anomalous score is computed, THEN THE Gateway SHALL return a `GatewayDecision` with an error reason and SHALL NOT return `action=ALLOW`.
8. THE Gateway SHALL attach the AnomalyScore normalized to [0.0, 1.0] to every `GatewayDecision`, regardless of the PolicyAction taken.
9. WHEN a request telemetry payload is missing one or more fields required to construct a TelemetryVector, THE Gateway SHALL return HTTP 422 Unprocessable Entity without invoking the BehaviorScorer or creating a session record.
10. WHEN a request telemetry payload contains fields that fail type or range validation, THE Gateway SHALL return HTTP 422 Unprocessable Entity without invoking the BehaviorScorer or creating a session record.
11. WHEN the PERIMETER_BLACKLIST is unavailable or throws an error during lookup, THE Gateway SHALL return HTTP 503 Service Unavailable and SHALL NOT process the request further.

---

### Requirement 2: Isolation Forest Anomaly Scoring

**User Story:** As a security engineer, I want user behavioral telemetry to be scored by an ML model at every request, so that anomalous access patterns are detected without requiring labeled attack data.

#### Acceptance Criteria

1. THE BehaviorScorer SHALL be fitted with a synthetic baseline dataset of at least 100 samples whose feature dimensionality matches the TelemetryVector feature count during application startup before any request is served.
2. WHEN a TelemetryVector is submitted to the BehaviorScorer, THE BehaviorScorer SHALL return an AnomalyScore normalized to the range [0.0, 1.0].
3. THE BehaviorScorer SHALL normalize the raw Isolation Forest decision function output by clamping the raw value to the range [-0.5, 0.5] and then mapping it to [0.0, 1.0] using the formula `(0.5 - clamped) / 1.0`, where a raw value of -0.5 maps to 1.0 and a raw value of +0.5 maps to 0.0.
4. THE BehaviorScorer SHALL be constructed with `n_estimators=100` and `contamination=0.05` as default parameters; these parameters SHALL be configurable at instantiation time.
5. WHEN `score_behavior()` is called and the model has never been fitted via `fit()`, THE BehaviorScorer SHALL raise a `NotFittedError`.
6. IF the model fitting was attempted via `fit()` but raised an exception, THEN THE BehaviorScorer SHALL propagate that exception to the caller rather than raising a `NotFittedError`.
7. THE BehaviorScorer SHALL produce a deterministic AnomalyScore for the same TelemetryVector input across multiple invocations against the same fitted model instance.
8. WHEN a TelemetryVector contains non-finite values (NaN or Infinity), THE BehaviorScorer SHALL reject the input and raise a `ValueError`.

---

### Requirement 3: TelemetryVector Validation

**User Story:** As a security engineer, I want all telemetry submitted to the system to be validated before ML inference, so that malformed data cannot cause model errors or bypass scoring.

#### Acceptance Criteria

1. WHEN a telemetry submission is received, THE Gateway SHALL validate that `click_speed_intervals` is a non-empty list of at most 1000 non-negative floating-point values before constructing a TelemetryVector.
2. WHEN a telemetry submission is received, THE Gateway SHALL validate that `page_path_weights` is a non-empty collection where all values are within the range [0.0, 1.0].
3. WHEN a telemetry submission is received, THE Gateway SHALL validate that every element of `sequence_transitions` is an integer in the range [1, 999999] representing an encoded page ID.
4. WHEN a telemetry submission is received, THE Gateway SHALL validate that `session_duration_ms` is a non-negative floating-point value no greater than 86400000 (24 hours in milliseconds).
5. WHEN a telemetry submission is received, THE Gateway SHALL validate that `request_rate_per_sec` is a non-negative floating-point value no greater than 10000.0.
6. IF any TelemetryVector field fails validation, THEN THE Gateway SHALL reject the request with HTTP 422 and an error response body that identifies which field failed validation, and SHALL NOT proceed to ML scoring.
7. THE TelemetryVector SHALL expose a `to_feature_array()` method that flattens all fields into a single numeric array in which every element is a finite floating-point value (not NaN and not infinite) suitable for ML inference.
8. IF `to_feature_array()` produces an array containing any NaN or infinite value, THEN THE Gateway SHALL treat this as a validation failure and SHALL NOT proceed to ML scoring.

---

### Requirement 4: In-Memory State Management

**User Story:** As a security architect, I want all session and blacklist state to reside exclusively in RAM with no disk writes, so that the system maintains forensic deniability and low-latency lookups.

#### Acceptance Criteria

1. THE system SHALL store all session data exclusively in the ACTIVE_SESSIONS in-memory dictionary and SHALL NOT write session records to any disk-based storage.
2. THE system SHALL store all blocked IP addresses exclusively in the PERIMETER_BLACKLIST in-memory set and SHALL NOT persist blacklist entries to any disk-based storage.
3. THE system SHALL complete all ACTIVE_SESSIONS lookups and writes in no more than 1 millisecond per operation under a load of up to 100,000 entries.
4. THE system SHALL complete all PERIMETER_BLACKLIST membership checks and additions in no more than 1 millisecond per operation under a load of up to 100,000 entries.
5. THE SessionRecord SHALL include fields: `session_id` (non-empty string), `ip_address` (valid IPv4 or IPv6 string), `role` (one of "Admin", "Engineer", or "Guest"), `anomaly_score` (float in [0.0, 1.0]), `status` (a `SessionStatus` value of `ACTIVE`, `REVOKED`, or `EXPIRED`), `created_at_ms` (Unix epoch milliseconds, non-negative), and `revoked_at_ms` (Unix epoch milliseconds or `None` before revocation).
6. WHEN a session is revoked, THE SessionRecord SHALL set `status` to `REVOKED` and record `revoked_at_ms` as the Unix epoch millisecond timestamp at the moment of revocation.
7. WHEN a SessionRecord has `status=REVOKED`, THE `revocation_delta_ms` property SHALL return the value `revoked_at_ms - created_at_ms`, and this value SHALL be non-negative.
8. IF a SessionRecord has a status other than `REVOKED`, THEN THE `revocation_delta_ms` property SHALL return `None`.
9. THE system SHALL expose a `SessionStatus` enumeration with members `ACTIVE`, `REVOKED`, and `EXPIRED`; a newly created SessionRecord SHALL have `status=ACTIVE`.

---

### Requirement 5: SOAR Automated Threat Response

**User Story:** As a SOC analyst, I want high-risk sessions to trigger an automated response pipeline that enriches threat data, blacklists the attacker IP, and revokes the session without manual intervention, so that threats are contained in real time.

#### Acceptance Criteria

1. WHEN the Gateway determines that an AnomalyScore is strictly greater than 0.75, THE SOAR_Engine SHALL be invoked with the attacker IP, session ID, and anomaly score.
2. WHEN triggered, THE SOAR_Engine SHALL query the AbuseIPDB REST API using the configured `ABUSEIPDB_API_KEY` with a network timeout of 5.0 seconds.
3. WHEN the AbuseIPDB query returns a successful HTTP response, THE SOAR_Engine SHALL construct an IPReputationReport containing the integer abuse confidence score in the range [0, 100] returned by the API and a source identifier of `"abuseipdb"`.
4. WHEN the AbuseIPDB query fails due to a network error, timeout, or non-success HTTP response, THE SOAR_Engine SHALL load the OfflineFallbackDB and construct an IPReputationReport with a source identifier of `"offline_fallback"`.
5. WHEN the OfflineFallbackDB file is missing or its contents cannot be parsed as valid JSON, THE SOAR_Engine SHALL construct an IPReputationReport with an abuse confidence score of 0 and a source identifier of `"offline_fallback_error"` and SHALL continue the response pipeline without raising an exception.
6. WHEN the reputation lookup step completes by any of the above outcomes, THE SOAR_Engine SHALL add the attacker IP to PERIMETER_BLACKLIST.
7. WHEN the attacker IP has been added to PERIMETER_BLACKLIST, THE SOAR_Engine SHALL set the corresponding SessionRecord status to `REVOKED` and record `revoked_at_ms` as the current UTC epoch milliseconds.
8. WHEN the session has been revoked, THE SOAR_Engine SHALL publish an AlertEvent of type `AI_ANOMALY` containing the source IP, anomaly score, abuse confidence score, session ID, and elapsed milliseconds between session creation and revocation.
9. IF blacklisting or session revocation fails during the pipeline, THEN THE SOAR_Engine SHALL log the failure, publish an AlertEvent with whatever enrichment data is available, and SHALL NOT suppress the alert publication.
10. THE `lookup_ip_reputation()` function SHALL never raise an exception for any string input; THE SOAR_Engine SHALL always return a valid IPReputationReport containing a non-empty source identifier and an integer abuse confidence score in [0, 100].

---

### Requirement 6: TokenWatcher Honeytoken Deception Daemon

**User Story:** As a SOC analyst, I want any access to the decoy credential file to be instantly detected and published as an alert, so that intruders who discover the honeytoken are fingerprinted and neutralized.

#### Acceptance Criteria

1. THE TokenWatcher SHALL monitor the parent directory `data/honey_tokens/` and filter to the HoneytokenFile `db_config.json`, detecting file created, modified, accessed, and deleted events on that file.
2. THE TokenWatcher SHALL run as a background daemon thread that is separate from the main asyncio event loop.
3. WHILE the TokenWatcher daemon is running, WHEN any filesystem event is detected on the HoneytokenFile, THE TokenWatcher SHALL publish exactly one `AlertEvent` of type `HONEYTOKEN_ACCESS` to the EventHub containing the affected file path and a `timestamp_ms` value in Unix epoch milliseconds.
4. WHEN publishing a filesystem event, THE TokenWatcher SHALL bridge from its watchdog OS thread into the asyncio event loop using `loop.call_soon_threadsafe` to enqueue the alert safely.
5. WHEN a filesystem event is detected on the HoneytokenFile, THE TokenWatcher SHALL record the OS-level process context (such as PID and user) in optional fields of the AlertEvent where that context is available from the OS event, and SHALL NOT attempt to add a source IP to PERIMETER_BLACKLIST because filesystem events carry no network IP address.
6. THE TokenWatcher SHALL ignore events on directories and SHALL only process events on files within the monitored path.
7. WHEN the application starts, THE TokenWatcher SHALL begin monitoring before the first inbound request is accepted.
8. WHEN the application starts and the HoneytokenFile does not yet exist, THE TokenWatcher SHALL monitor the parent directory for a file creation event and SHALL begin treating the newly created file as the HoneytokenFile upon its creation.

---

### Requirement 7: PortTrap TCP Decoy Daemon

**User Story:** As a SOC analyst, I want any TCP connection attempt on the RDP decoy port to be silently logged and alerted without revealing the deception infrastructure, so that network scanners and RDP-targeting attackers are fingerprinted.

#### Acceptance Criteria

1. THE PortTrap SHALL bind an async TCP server to port 3389 within the asyncio event loop at application startup.
2. WHEN an inbound TCP connection is received on port 3389, THE PortTrap SHALL accept the connection, record the source IP address and a `timestamp_ms` value in Unix epoch milliseconds, and add the source IP to PERIMETER_BLACKLIST.
3. WHEN an inbound TCP connection is received, THE PortTrap SHALL publish an `AlertEvent` of type `PORT_TRAP` to the EventHub containing the source IP, port number 3389, and timestamp.
4. WHEN an inbound TCP connection is received, THE PortTrap SHALL close the connection within 100 milliseconds of acceptance and SHALL transmit zero bytes of data to the connecting client before closing.
5. IF port 3389 is already in use when the application starts, THEN THE system SHALL log a startup warning that includes the port number, skip the PortTrap daemon, and continue initializing all other subsystems normally.
6. THE PortTrap SHALL handle each connection as an independent asyncio task so that a single slow or hanging connection does not block detection of subsequent connection attempts.

---

### Requirement 8: EventHub Publish-Subscribe Bus

**User Story:** As a system architect, I want all alert-producing subsystems to share a single event bus that decouples producers from WebSocket consumers, so that deception daemons and the gateway can publish events without knowing about connected SOC clients.

#### Acceptance Criteria

1. THE EventHub SHALL maintain a singleton `asyncio.Queue` instance as its backing store for alert events.
2. WHEN `publish()` is called with an AlertEvent, THE EventHub SHALL enqueue the event without blocking the calling coroutine.
3. THE EventHub SHALL fan out each dequeued AlertEvent to all active WebSocket subscriber coroutines and SHALL increment a delivery count by the number of active subscribers reached for each event delivered.
4. WHEN a WebSocket subscriber disconnects during a fan-out operation, THE EventHub SHALL remove the disconnected subscriber from the active list and SHALL continue broadcasting to remaining subscribers without interruption.
5. THE EventHub SHALL support publishing from both asyncio coroutines and OS-level background threads; publishing from a background thread SHALL use `loop.call_soon_threadsafe` to enqueue the event into the asyncio event loop.
6. THE EventHub SHALL preserve the ordering of events such that all subscribers receive events in the order they were published.

---

### Requirement 9: SOC WebSocket Stream

**User Story:** As a SOC analyst, I want a persistent WebSocket connection to the backend that pushes all alert events to the dashboard in real time, so that I receive millisecond-precision telemetry without polling.

#### Acceptance Criteria

1. THE SOCStreamHandler SHALL expose a WebSocket endpoint at `/api/soc/stream` on the FastAPI backend.
2. WHEN a client attempts to establish a WebSocket connection, THE SOCStreamHandler SHALL validate the `SOC_MASTER_SECRET` token before completing the WebSocket upgrade.
3. IF the provided token does not match `SOC_MASTER_SECRET`, THEN THE SOCStreamHandler SHALL reject the connection with HTTP 403 Forbidden before the WebSocket upgrade is completed.
4. WHEN a WebSocket connection is established, THE SOCStreamHandler SHALL register the connection as a subscriber to the EventHub such that the connection is immediately eligible to receive all subsequent messages without any additional activation step.
5. WHEN an AlertEvent is available in the EventHub and a WebSocket connection is subscribed, THE SOCStreamHandler SHALL relay the AlertEvent as a JSON-serialized message to the connected client within 500 milliseconds of the event being published to the EventHub.
6. WHEN a connected SOC client disconnects, THE SOCStreamHandler SHALL remove the disconnected client from the EventHub subscriber list and SHALL continue relaying events to all remaining connected clients without interruption.
7. WHEN the AlertEvent `to_json()` method encounters a field that cannot be serialized to JSON, THE SOCStreamHandler SHALL raise a serialization error and SHALL NOT transmit a partial or malformed message to the client.

---

### Requirement 10: Corporate Portal Decoy Frontend

**User Story:** As a security operator, I want a convincing public-facing web portal that presents realistic corporate UI to attackers, so that adversaries are drawn in and kept engaged long enough for the deception system to fingerprint and alert on them.

#### Acceptance Criteria

1. THE CorporatePortal SHALL be a React single-page application built with Vite and TailwindCSS accessible over HTTPS.
2. THE CorporatePortal SHALL present a login interface that collects at minimum a username, password, and user role, and submits authentication requests to the Gateway at `POST /api/auth`.
3. WHEN submitting an authentication request, THE CorporatePortal SHALL include a TelemetryVector payload populated with: `click_speed_intervals` derived from click timing events, `page_path_weights` from page navigation frequency, `sequence_transitions` from the sequence of pages visited, `session_duration_ms` from the session elapsed time, and `request_rate_per_sec` from the request frequency.
4. WHEN the Gateway returns HTTP 403, THE CorporatePortal SHALL display a generic access-denied message that contains no reference to honeypots, deception systems, monitoring, security analysis, system identifiers, component names, or backend error details.
5. WHEN the Gateway returns HTTP 422, HTTP 5xx, or a network failure occurs, THE CorporatePortal SHALL display a generic error message and SHALL NOT expose any backend error details or internal system information to the user.
6. THE CorporatePortal SHALL NOT expose any WebSocket endpoints, alert data, session records, blacklist entries, backend route paths, or internal system information regardless of the network from which it is accessed.

---

### Requirement 11: SOC Dashboard Private Frontend

**User Story:** As a SOC analyst, I want a local-only dashboard that displays live alerts, session state, and blacklist entries with sub-second latency, so that I can monitor and respond to threats in real time.

#### Acceptance Criteria

1. THE SOCDashboard SHALL be a React single-page application built with Vite, TailwindCSS, and Recharts accessible only from localhost (`127.0.0.1` / `::1`) network interfaces.
2. THE SOCDashboard SHALL establish a persistent WebSocket connection to `/api/soc/stream` passing the `SOC_MASTER_SECRET` as an authentication token.
3. WHEN an AlertEvent is received over the WebSocket, THE SOCDashboard SHALL display the alert in the live alert feed within the same React render cycle that processes the incoming message.
4. THE SOCDashboard SHALL display for each alert: the alert type, source IP, and `timestamp_ms` (for all alert types); the anomaly score and revocation delta (for `AI_ANOMALY` events only); and the affected file path (for `HONEYTOKEN_ACCESS` events only).
5. WHEN the WebSocket connection is lost, THE SOCDashboard SHALL schedule exactly one reconnection attempt after a fixed delay of 2000 milliseconds and SHALL NOT schedule additional reconnection attempts until the current reconnection attempt either succeeds or fails.
6. THE SOCDashboard SHALL display the current PERIMETER_BLACKLIST entries in a grid that updates within the current render cycle whenever the backend pushes a blacklist-change event.
7. THE SOCDashboard server SHALL bind exclusively to `127.0.0.1` (or `::1` for IPv6 localhost) and SHALL NOT bind to `0.0.0.0` or any external network interface.

---

### Requirement 12: AlertEvent Data Model and Serialization

**User Story:** As a developer, I want all alert events to be serialized to a consistent JSON format before WebSocket transmission, so that the SOC dashboard can reliably parse and display every alert type without schema mismatches.

#### Acceptance Criteria

1. THE AlertEvent SHALL include required fields: `alert_type` (string value of `AlertType` enum), `source_ip` (non-empty string), and `timestamp_ms` (non-negative float representing Unix epoch milliseconds).
2. THE AlertEvent SHALL include optional fields: `session_id`, `anomaly_score`, `affected_path`, `port`, `abuse_score`, and `revocation_delta_ms`, each of which SHALL default to `None` when not set.
3. WHEN an `AI_ANOMALY` AlertEvent is constructed by the SOAR_Engine, the fields `session_id` (non-empty string), `anomaly_score` (float in [0.0, 1.0]), `abuse_score` (integer in [0, 100]), and `revocation_delta_ms` (non-negative float) SHALL all be non-None.
4. WHEN a `HONEYTOKEN_ACCESS` AlertEvent is constructed by the TokenWatcher, the `affected_path` field SHALL be non-None and SHALL contain the absolute path of the accessed honeytoken file.
5. WHEN a `PORT_TRAP` AlertEvent is constructed by the PortTrap, the `port` field SHALL be non-None and SHALL equal 3389.
6. THE AlertEvent `to_json()` method SHALL produce a JSON-serializable dictionary containing all non-None fields, with `alert_type` serialized as its string enum value.
7. FOR ALL valid AlertEvent objects of any AlertType, serializing via `to_json()` and then constructing an equivalent object from the resulting dictionary SHALL produce an object where all non-None fields are equal to those of the original.

---

### Requirement 13: Secrets and Configuration Management

**User Story:** As a security architect, I want all sensitive credentials to be injected exclusively via environment variables, so that no secrets are ever hardcoded, committed to version control, or persisted to disk.

#### Acceptance Criteria

1. THE system SHALL read the AbuseIPDB API key exclusively from the `ABUSEIPDB_API_KEY` environment variable and SHALL NOT accept it from configuration files, hardcoded values, or any other source.
2. THE system SHALL read the SOC master secret exclusively from the `SOC_MASTER_SECRET` environment variable and SHALL NOT accept it from configuration files, hardcoded values, or any other source.
3. THE system SHALL read the runtime environment flag exclusively from the `FASTAPI_ENV` environment variable to determine behavior such as CORS policy and debug mode.
4. THE system SHALL provide a `.env.example` file at the repository root containing clearly labeled placeholder values (not real secrets) for `ABUSEIPDB_API_KEY`, `SOC_MASTER_SECRET`, and `FASTAPI_ENV`.
5. THE repository SHALL NOT contain any file that includes real values for `ABUSEIPDB_API_KEY` or `SOC_MASTER_SECRET` at any commit in version control history.
6. WHEN all required environment variables (`ABUSEIPDB_API_KEY`, `SOC_MASTER_SECRET`, `FASTAPI_ENV`) are present and non-empty at startup, THE system SHALL proceed to serve requests without any additional blocking validation phase.
7. WHEN any required environment variable is absent or empty at startup, THE system SHALL refuse to register request-handling routes and SHALL raise an `EnvironmentError` with a message that names the missing or empty variable.
8. IF raising the `EnvironmentError` itself fails, THEN THE system SHALL still not accept any inbound requests.

---

### Requirement 14: Application Startup and Lifecycle

**User Story:** As a DevOps engineer, I want all subsystems to be initialized in a defined order at startup and to start accepting requests only when all critical components are ready, so that no request is processed in a partially-initialized state.

#### Acceptance Criteria

1. WHEN the application starts, THE system SHALL fit the BehaviorScorer with a synthetic baseline dataset and SHALL NOT register any request-handling routes as active until fitting completes successfully.
2. WHEN the application starts, THE EventHub singleton SHALL be initialized before the TokenWatcher, PortTrap, or SOCStreamHandler are instantiated; IF any of these components is instantiated before EventHub initialization, THEN THE system SHALL raise an error.
3. WHEN the application starts, THE TokenWatcher SHALL begin monitoring the HoneytokenFile before the first inbound request is accepted.
4. WHEN the application starts and port 3389 is already in use, THE system SHALL log a startup warning that includes the port number, skip the PortTrap daemon, and continue initializing all remaining subsystems.
5. THE system SHALL use the FastAPI `startup` lifecycle event to orchestrate the initialization sequence in the following order: (1) validate environment variables, (2) initialize EventHub, (3) fit BehaviorScorer, (4) start TokenWatcher, (5) start PortTrap, (6) register request-handling routes.
6. WHEN the application receives a shutdown signal, THE system SHALL call `stop()` on the TokenWatcher daemon thread and SHALL wait for the thread to terminate before the process exits.

---

### Requirement 15: CORS and Network Isolation

**User Story:** As a security architect, I want strict network-level access controls on both frontends and the backend, so that the SOC console is never reachable from public networks and the backend is only callable by the Corporate Portal.

#### Acceptance Criteria

1. THE FastAPI backend SHALL configure CORS middleware with an `allow_origins` list restricted to only the CorporatePortal's origin hostname; WHEN a cross-origin request arrives from any unlisted origin, THE CORS middleware SHALL reject the request and SHALL NOT pass it to any route handler.
2. THE SOCDashboard dev server and any production serving configuration SHALL bind exclusively to `127.0.0.1` (or `::1`) and SHALL NOT bind to `0.0.0.0` or any routable external interface.
3. WHEN the system is in a production deployment, THE CorporatePortal SHALL communicate with the FastAPI backend exclusively over HTTPS (TLS); IF an HTTP (non-TLS) request reaches the backend in production, THEN THE backend SHALL redirect or reject it before processing.
4. THE SOCStreamHandler WebSocket endpoint at `/api/soc/stream` SHALL only accept connection attempts originating from `127.0.0.1` or `::1`; WHEN a connection attempt arrives from any non-localhost IP address, THE SOCStreamHandler SHALL refuse the connection before the WebSocket upgrade is completed.
