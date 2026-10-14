import React, { useEffect, useRef, useState } from "react";

// ── Types ──────────────────────────────────────────────────────────────────
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
  server_ts_ms?: number;
}

interface BanRow {
  ip: string;
  trigger: string;
  score: string;
  abuse: string;
  ts: string;
}

// ── Styles ─────────────────────────────────────────────────────────────────
const S = {
  page: {
    background: "var(--bg)", height: "calc(100vh - 45px)",
    display: "flex", flexDirection: "column" as const, overflow: "hidden",
  },
  subhdr: {
    background: "#060a0f", borderBottom: "1px solid var(--bd)",
    padding: "7px 16px", fontSize: 10, color: "var(--mu)",
    textTransform: "uppercase" as const, letterSpacing: ".08em",
    display: "flex", alignItems: "center", justifyContent: "space-between",
    flexShrink: 0,
  },
  body: { display: "flex", flex: 1, overflow: "hidden" },
  sidebar: {
    width: 200, borderRight: "1px solid var(--bd)",
    padding: 12, display: "flex", flexDirection: "column" as const,
    gap: 12, flexShrink: 0, overflowY: "auto" as const,
  },
  mc: {
    background: "#0d1117", border: "1px solid var(--bd)",
    borderRadius: 8, padding: "10px 14px", textAlign: "center" as const,
  },
  main: { flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" as const },
  terminal: {
    flex: 1, overflowY: "auto" as const, padding: "10px 14px",
    fontFamily: "'Cascadia Code','Fira Code','Courier New',monospace",
    fontSize: 11, background: "#060a0f", color: "#7a8a99",
  },
  bottom: {
    height: 210, borderTop: "1px solid var(--bd)",
    flexShrink: 0, overflowY: "auto" as const,
  },
  wsBadge: (live: boolean): React.CSSProperties => ({
    padding: "3px 8px", borderRadius: 8, fontSize: 10,
    background: live ? "#0d1f14" : "#1c2630",
    color: live ? "var(--ok)" : "var(--mu)",
  }),
  intelBadge: {
    display: "inline-flex", alignItems: "center", gap: 5,
    padding: "2px 8px", borderRadius: 8, fontSize: 10,
    background: "#161a20", border: "1px solid var(--bd)", color: "var(--mu)",
  },
};

// ── Component ──────────────────────────────────────────────────────────────
export default function SOCDashboard() {
  const [wsLive, setWsLive]       = useState(false);
  const [logs, setLogs]           = useState<string[]>(["-- awaiting events --"]);
  const [banRows, setBanRows]     = useState<BanRow[]>([]);
  const [metrics, setMetrics]     = useState({
    sessions: 0, banned: 0, evicted: 0, alerts: 0, portHits: 0, honeyHits: 0,
  });
  const bannedSet  = useRef(new Set<string>());
  const termRef    = useRef<HTMLDivElement>(null);
  const wsRef      = useRef<WebSocket | null>(null);
  const reconnRef  = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── WS connection ────────────────────────────────────────────────────────
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
    const ws = new WebSocket("ws://127.0.0.1:8000");
    wsRef.current = ws;
    ws.onopen  = () => { setWsLive(true);  addLog("SOC stream connected.", "ok"); };
    ws.onclose = () => {
      setWsLive(false);
      addLog("Connection lost — reconnecting in 2 s", "warn");
      reconnRef.current = setTimeout(connect, 2000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (e) => {
      try { handleEvent(JSON.parse(e.data) as AlertEvent); }
      catch { addLog("Parse error: " + e.data, "warn"); }
    };
  }

  // ── Event handler ────────────────────────────────────────────────────────
  function handleEvent(d: AlertEvent) {
    const t  = d.alert_type || "?";
    const ip = d.source_ip  || "?";
    const ts = d.timestamp_ms ? new Date(d.timestamp_ms).toLocaleTimeString() : "--";
    const sc = d.anomaly_score != null ? d.anomaly_score.toFixed(4) : "--";
    const ab = d.abuse_score  != null ? String(d.abuse_score) : "--";

    let msg = "";
    let level: "info" | "warn" | "critical" | "ok" = "warn";

    if (t === "AI_ANOMALY") {
      level = "critical";
      msg   = `AI_ANOMALY | ip=${ip} score=${sc} abuse=${ab} delta=${(d.revocation_delta_ms ?? 0).toFixed(2)}ms`;
      setMetrics(m => ({ ...m, evicted: m.evicted + 1, alerts: m.alerts + 1 }));
      addBanRow(ip, "AI_ANOMALY", sc, ab, ts);
      if (!bannedSet.current.has(ip)) {
        bannedSet.current.add(ip);
        setMetrics(m => ({ ...m, banned: bannedSet.current.size }));
      }
    } else if (t === "HONEYTOKEN_ACCESS") {
      msg = `HONEYTOKEN_ACCESS | file=${d.affected_path ?? "db_config.json"} ip=${ip}`;
      setMetrics(m => ({ ...m, honeyHits: m.honeyHits + 1, alerts: m.alerts + 1 }));
      addBanRow(ip, "HONEYTOKEN", "--", "--", ts);
    } else if (t === "PORT_TRAP") {
      msg = `PORT_TRAP | ip=${ip} port=${d.port ?? 3389}`;
      setMetrics(m => ({ ...m, portHits: m.portHits + 1, alerts: m.alerts + 1 }));
      if (!bannedSet.current.has(ip)) {
        bannedSet.current.add(ip);
        setMetrics(m => ({ ...m, banned: bannedSet.current.size }));
      }
      addBanRow(ip, "PORT_TRAP", "--", "--", ts);
    } else {
      msg = JSON.stringify(d).slice(0, 120);
    }
    addLog(msg, level);
  }

  // ── Log helpers ──────────────────────────────────────────────────────────
  function addLog(msg: string, level: "info" | "warn" | "critical" | "ok") {
    const clr = { info:"#58a6ff", warn:"#e3b341", critical:"#f85149", ok:"#3fb950" }[level];
    const lbl = { info:"INFO", warn:"WARN", critical:"CRIT", ok:"OK  " }[level];
    const now = new Date().toISOString().split("T")[1].split(".")[0];
    const line = `\u001b[${now}] [${lbl}] ${msg}`;
    setLogs(prev => {
      const next = [...prev.slice(-299), line];
      return next;
    });
    setTimeout(() => {
      if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
    }, 10);
  }

  function addBanRow(ip: string, trigger: string, sc: string, ab: string, ts: string) {
    setBanRows(prev => [{ ip, trigger, score: sc, abuse: ab, ts }, ...prev.slice(0, 49)]);
  }

  // ── Status poll ──────────────────────────────────────────────────────────
  async function loadStatus() {
    try {
      const r = await fetch("/api/status");
      const d = await r.json();
      setMetrics(m => ({
        ...m,
        sessions: d.sessions?.length ?? 0,
        banned:   d.banned_ips?.length ?? 0,
        alerts:   d.alert_count ?? m.alerts,
      }));
      bannedSet.current = new Set((d.banned_ips ?? []).map((b: any) => b.ip));
    } catch {}
  }

  // ── Render ───────────────────────────────────────────────────────────────
  return (
    <div style={S.page}>

      {/* Sub-header */}
      <div style={S.subhdr}>
        <span>&#9650; Security Operations Center &mdash; RESTRICTED</span>
        <div style={{ display:"flex", gap:10, alignItems:"center" }}>
          <span style={S.intelBadge}>
            <span style={{width:6,height:6,borderRadius:"50%",background:"var(--wn)",display:"inline-block"}}/>
            AbuseIPDB: OFFLINE_MOCK (0 Req)
          </span>
          <span style={S.wsBadge(wsLive)}>{wsLive ? "● Live" : "● Offline"}</span>
        </div>
      </div>

      <div style={S.body}>

        {/* Sidebar */}
        <div style={S.sidebar}>
          {[
            ["m-sess",  metrics.sessions, "Active Sessions",  "var(--ac)"],
            ["m-ban",   metrics.banned,   "Banned IPs",       "var(--dr)"],
            ["m-evict", metrics.evicted,  "Evicted Sessions", "var(--wn)"],
            ["m-alert", metrics.alerts,   "Total Alerts",     "var(--ac)"],
            ["m-port",  metrics.portHits, "Port Trap Hits",   "var(--wn)"],
            ["m-honey", metrics.honeyHits,"Honeytoken Trips", "var(--dr)"],
          ].map(([id, val, label, clr]) => (
            <div key={String(id)} style={S.mc}>
              <div style={{ fontSize:24, fontWeight:700, color:String(clr) }}>{String(val)}</div>
              <div style={{ fontSize:10, color:"var(--mu)", marginTop:2 }}>{String(label)}</div>
            </div>
          ))}
          <button
            onClick={loadStatus}
            style={{ background:"transparent", border:"1px solid var(--bd)", color:"var(--mu)",
                     padding:"6px", fontSize:11, marginTop:"auto" }}>
            &#8635; Refresh
          </button>
        </div>

        {/* Main panel */}
        <div style={S.main}>
          <div style={S.subhdr}>
            <span>&#9654; Live Event Stream</span>
            <button
              onClick={() => setLogs(["-- cleared --"])}
              style={{ background:"transparent", border:"1px solid var(--bd)",
                       color:"var(--mu)", padding:"2px 8px", fontSize:10 }}>
              Clear
            </button>
          </div>

          {/* Terminal */}
          <div ref={termRef} style={S.terminal}>
            {logs.map((line, i) => {
              const isAnsi = line.startsWith("\u001b[");
              const clean  = isAnsi ? line.slice(1) : line;
              const clr    = clean.includes("[CRIT]") ? "var(--dr)"
                           : clean.includes("[WARN]") ? "var(--wn)"
                           : clean.includes("[OK  ]") ? "var(--ok)"
                           : clean.startsWith("-- ") ? "#2e3a48"
                           : "var(--ac)";
              return (
                <div key={i} style={{ lineHeight:1.65, color: "var(--mu)" }}>
                  {clean.split("] ").map((part, j) => (
                    <span key={j} style={{ color: j === 1 ? clr : "#2e3a48" }}>
                      {part}{j < clean.split("] ").length - 1 ? "] " : ""}
                    </span>
                  ))}
                </div>
              );
            })}
          </div>

          {/* Ban table */}
          <div style={S.bottom}>
            <div style={S.subhdr}>&#128683; Banned / Revoked IPs</div>
            <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
              <thead>
                <tr>
                  {["IP Address","Trigger","Anomaly","AbuseIPDB","Time"].map(h => (
                    <th key={h} style={{ textAlign:"left", padding:"6px 12px",
                                         color:"var(--mu)", fontWeight:600,
                                         background:"var(--s)", borderBottom:"1px solid var(--bd)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {banRows.length === 0 ? (
                  <tr><td colSpan={5} style={{ color:"var(--mu)", textAlign:"center", padding:12 }}>
                    No events yet.
                  </td></tr>
                ) : banRows.map((r, i) => (
                  <tr key={i}>
                    <td style={{ padding:"5px 12px", fontFamily:"monospace", color:"var(--dr)",
                                  borderBottom:"1px solid #0f141a" }}>{r.ip}</td>
                    <td style={{ padding:"5px 12px", borderBottom:"1px solid #0f141a" }}>
                      <span style={{ background:"#2d1213", color:"var(--dr)",
                                      padding:"1px 6px", borderRadius:8, fontSize:9,
                                      fontWeight:700 }}>{r.trigger}</span>
                    </td>
                    <td style={{ padding:"5px 12px", color:"var(--mu)",
                                  borderBottom:"1px solid #0f141a" }}>{r.score}</td>
                    <td style={{ padding:"5px 12px", color:"var(--mu)",
                                  borderBottom:"1px solid #0f141a" }}>
                      {r.abuse === "--" ? r.abuse : (
                        <span style={{ background:"#221a08", color:"var(--wn)",
                                        padding:"1px 6px", borderRadius:8, fontSize:9,
                                        fontWeight:700 }}>{r.abuse}</span>
                      )}
                    </td>
                    <td style={{ padding:"5px 12px", color:"var(--mu)",
                                  borderBottom:"1px solid #0f141a" }}>{r.ts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
