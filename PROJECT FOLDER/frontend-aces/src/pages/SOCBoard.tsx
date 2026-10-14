import React, { useEffect, useRef, useState } from "react";

// SOC Board -- mounted only when RequireAdmin guard has already passed.
// If rendered without admin role, App.tsx renders ForbiddenPage instead.
// This component never issues a redirect -- the guard handles access control.

interface AlertEvent {
  alert_type: string;
  source_ip: string;
  timestamp_ms: number;
  anomaly_score?: number;
  abuse_score?: number;
  affected_path?: string;
  port?: number;
  revocation_delta_ms?: number;
  session_id?: string;
}

interface BanRow { ip: string; trigger: string; score: string; abuse: string; ts: string; }

export default function SOCBoard() {
  const [wsLive, setWsLive]   = useState(false);
  const [logs, setLogs]       = useState<string[]>(["-- awaiting events --"]);
  const [banRows, setBanRows] = useState<BanRow[]>([]);
  const [metrics, setMetrics] = useState({
    sessions: 0, banned: 0, evicted: 0, alerts: 0, portHits: 0, honeyHits: 0,
  });
  const bannedSet = useRef(new Set<string>());
  const termRef   = useRef<HTMLDivElement>(null);
  const wsRef     = useRef<WebSocket | null>(null);
  const reconnRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    connect();
    const iv = setInterval(loadStatus, 10_000);
    loadStatus();
    return () => {
      clearInterval(iv);
      wsRef.current?.close();
      if (reconnRef.current) clearTimeout(reconnRef.current);
    };
  }, []);

  function connect() {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}`);
    wsRef.current = ws;
    ws.onopen  = () => { setWsLive(true);  addLog("SOC stream connected.", "ok"); };
    ws.onclose = () => {
      setWsLive(false);
      addLog("Connection lost -- reconnecting in 2s", "warn");
      reconnRef.current = setTimeout(connect, 2000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = e => {
      try { handleEvent(JSON.parse(e.data) as AlertEvent); }
      catch { addLog("Parse error: " + e.data, "warn"); }
    };
  }

  function handleEvent(d: AlertEvent) {
    const t  = d.alert_type || "?";
    const ip = d.source_ip  || "?";
    const ts = d.timestamp_ms ? new Date(d.timestamp_ms).toLocaleTimeString() : "--";
    const sc = d.anomaly_score != null ? d.anomaly_score.toFixed(4) : "--";
    const ab = d.abuse_score  != null ? String(d.abuse_score) : "--";
    let msg = "", level: "info"|"warn"|"critical"|"ok" = "warn";

    if (t === "AI_ANOMALY") {
      level = "critical";
      msg   = `AI_ANOMALY | ip=${ip} score=${sc} abuse=${ab} delta=${(d.revocation_delta_ms ?? 0).toFixed(2)}ms`;
      setMetrics(m => ({ ...m, evicted: m.evicted + 1, alerts: m.alerts + 1 }));
      addBanRow(ip, "AI_ANOMALY", sc, ab, ts);
      if (!bannedSet.current.has(ip)) { bannedSet.current.add(ip); setMetrics(m => ({ ...m, banned: bannedSet.current.size })); }
    } else if (t === "HONEYTOKEN_ACCESS") {
      msg = `HONEYTOKEN | file=${d.affected_path ?? "db_config.json"} ip=${ip}`;
      setMetrics(m => ({ ...m, honeyHits: m.honeyHits + 1, alerts: m.alerts + 1 }));
      addBanRow(ip, "HONEYTOKEN", "--", "--", ts);
    } else if (t === "PORT_TRAP") {
      msg = `PORT_TRAP | ip=${ip} port=${d.port ?? 3389}`;
      setMetrics(m => ({ ...m, portHits: m.portHits + 1, alerts: m.alerts + 1 }));
      if (!bannedSet.current.has(ip)) { bannedSet.current.add(ip); setMetrics(m => ({ ...m, banned: bannedSet.current.size })); }
      addBanRow(ip, "PORT_TRAP", "--", "--", ts);
    } else { msg = JSON.stringify(d).slice(0, 120); }
    addLog(msg, level);
  }

  function addLog(msg: string, level: "info"|"warn"|"critical"|"ok") {
    const lbl = { info:"INFO", warn:"WARN", critical:"CRIT", ok:"OK  " }[level];
    const now = new Date().toISOString().split("T")[1].split(".")[0];
    setLogs(prev => [...prev.slice(-299), `[${now}][${lbl}] ${msg}`]);
    setTimeout(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight; }, 10);
  }

  function addBanRow(ip: string, trigger: string, sc: string, ab: string, ts: string) {
    setBanRows(prev => [{ ip, trigger, score: sc, abuse: ab, ts }, ...prev.slice(0, 49)]);
  }

  async function loadStatus() {
    try {
      const r = await fetch("/api/status", { credentials: "include" });
      const d = await r.json();
      setMetrics(m => ({ ...m, sessions: d.sessions?.length ?? 0, banned: d.banned_ips?.length ?? 0, alerts: d.alert_count ?? m.alerts }));
      bannedSet.current = new Set((d.banned_ips ?? []).map((b: { ip: string }) => b.ip));
    } catch {}
  }

  const c = (id: string) => document.getElementById(id);

  return (
    <div style={{ background: "#060a0f", height: "calc(100vh - 43px)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* Sub-header */}
      <div style={{ background: "#0d1117", borderBottom: "1px solid #21262d", padding: "7px 16px", fontSize: 10, color: "var(--mu)", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0 }}>
        <span>&#9654; LIVE EVENT STREAM</span>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "2px 8px", borderRadius: 8, fontSize: 10, background: "#161a20", border: "1px solid #21262d", color: "var(--mu)" }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--wn)", display: "inline-block" }} />
            AbuseIPDB: OFFLINE_MOCK
          </span>
          <span style={{ padding: "3px 8px", borderRadius: 8, fontSize: 10, background: wsLive ? "#0d1f14" : "#1c2630", color: wsLive ? "var(--ok)" : "var(--mu)" }}>
            {wsLive ? "● Live" : "● Offline"}
          </span>
        </div>
      </div>

      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        {/* Sidebar */}
        <div style={{ width: 200, borderRight: "1px solid #21262d", padding: 12, display: "flex", flexDirection: "column", gap: 12, flexShrink: 0, overflowY: "auto" }}>
          {[
            [metrics.sessions, "Active Sessions",  "var(--ac)"],
            [metrics.banned,   "Banned IPs",        "var(--dr)"],
            [metrics.evicted,  "Evicted Sessions",  "var(--wn)"],
            [metrics.alerts,   "Total Alerts",      "var(--ac)"],
            [metrics.portHits, "Port Trap Hits",    "var(--wn)"],
            [metrics.honeyHits,"Honeytoken Trips",  "var(--dr)"],
          ].map(([val, label, clr]) => (
            <div key={String(label)} style={{ background: "#161b22", border: "1px solid #21262d", borderRadius: 8, padding: "10px 14px", textAlign: "center" }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: String(clr) }}>{String(val)}</div>
              <div style={{ fontSize: 10, color: "var(--mu)", marginTop: 2 }}>{String(label)}</div>
            </div>
          ))}
          <button onClick={loadStatus} style={{ background: "transparent", border: "1px solid #21262d", color: "var(--mu)", padding: 7, fontSize: 11, marginTop: "auto", cursor: "pointer" }}>
            &#8635; Refresh
          </button>
        </div>

        {/* Main */}
        <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
          {/* Terminal */}
          <div style={{ background: "#0d1117", borderBottom: "1px solid #21262d", padding: "6px 13px", fontSize: 10, color: "var(--mu)", display: "flex", justifyContent: "space-between", flexShrink: 0 }}>
            <span>&#9654; Event Log</span>
            <button onClick={() => setLogs(["-- cleared --"])} style={{ background: "transparent", border: "1px solid #21262d", color: "var(--mu)", padding: "1px 8px", fontSize: 10, cursor: "pointer" }}>Clear</button>
          </div>
          <div ref={termRef} style={{ flex: 1, overflowY: "auto", padding: "9px 13px", fontFamily: "'Cascadia Code','Fira Code',monospace", fontSize: 11, background: "#060a0f", color: "#7a8a99" }}>
            {logs.map((line, i) => {
              const clr = line.includes("[CRIT]") ? "var(--dr)" : line.includes("[WARN]") ? "var(--wn)" : line.includes("[OK  ]") ? "var(--ok)" : line.startsWith("-- ") ? "#2e3a48" : "var(--ac)";
              return <div key={i} style={{ lineHeight: 1.65, color: clr }}>{line}</div>;
            })}
          </div>

          {/* Ban table */}
          <div style={{ height: 210, borderTop: "1px solid #21262d", flexShrink: 0, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            <div style={{ background: "#0d1117", borderBottom: "1px solid #21262d", padding: "6px 13px", fontSize: 10, color: "var(--mu)", flexShrink: 0 }}>
              &#128683; Banned / Revoked IPs
            </div>
            <div style={{ overflowY: "auto", flex: 1 }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
                <thead>
                  <tr>{["IP Address","Trigger","Anomaly","AbuseIPDB","Time"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "6px 12px", color: "var(--mu)", fontWeight: 600, background: "var(--s)", borderBottom: "1px solid #21262d" }}>{h}</th>
                  ))}</tr>
                </thead>
                <tbody>
                  {banRows.length === 0 ? (
                    <tr><td colSpan={5} style={{ color: "var(--mu)", textAlign: "center", padding: 10 }}>No events yet.</td></tr>
                  ) : banRows.map((r, i) => (
                    <tr key={i}>
                      <td style={{ padding: "5px 12px", fontFamily: "monospace", color: "var(--dr)", borderBottom: "1px solid #0f141a" }}>{r.ip}</td>
                      <td style={{ padding: "5px 12px", borderBottom: "1px solid #0f141a" }}>
                        <span style={{ background: "#2d1213", color: "var(--dr)", padding: "1px 6px", borderRadius: 8, fontSize: 9, fontWeight: 700 }}>{r.trigger}</span>
                      </td>
                      <td style={{ padding: "5px 12px", color: "var(--mu)", borderBottom: "1px solid #0f141a" }}>{r.score}</td>
                      <td style={{ padding: "5px 12px", color: "var(--mu)", borderBottom: "1px solid #0f141a" }}>
                        {r.abuse === "--" ? r.abuse : <span style={{ background: "#221a08", color: "var(--wn)", padding: "1px 6px", borderRadius: 8, fontSize: 9, fontWeight: 700 }}>{r.abuse}</span>}
                      </td>
                      <td style={{ padding: "5px 12px", color: "var(--mu)", borderBottom: "1px solid #0f141a" }}>{r.ts}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
