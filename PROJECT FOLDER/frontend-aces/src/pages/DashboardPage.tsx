import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useHardBlock } from "../hooks/useAuth";

// Unified portal for ALL authenticated users.
// - client_user / eng_user: standard financial portal tabs only.
// - admin_user: same financial portal + an additional "Admin Controls" tab.
// The admin tab is invisible at the HTML level for non-admin users.

type Tab = "overview" | "transactions" | "statements" | "admin";

const card = (extra?: React.CSSProperties): React.CSSProperties => ({
  background: "var(--s)", border: "1px solid var(--bd)", borderRadius: 10,
  padding: 20, marginBottom: 16, ...extra,
});

const tabStyle = (active: boolean, warn?: boolean): React.CSSProperties => ({
  padding: "7px 18px", borderRadius: "6px 6px 0 0", fontSize: 13,
  fontWeight: active ? 700 : 400,
  background: active ? "var(--s)" : "transparent",
  border: active ? "1px solid var(--bd)" : "1px solid transparent",
  borderBottom: active ? "1px solid var(--s)" : "none",
  color: warn ? "var(--wn)" : (active ? "var(--tx)" : "var(--mu)"),
  cursor: "pointer", marginRight: 4,
});

export default function DashboardPage() {
  const role    = localStorage.getItem("aces_role")  || "Guest";
  const uname   = localStorage.getItem("aces_user")  || "User";
  const token   = localStorage.getItem("aces_token") || "";
  const isAdmin = role === "Admin";

  const [tab, setTab]   = useState<Tab>("overview");
  const [score, setScore] = useState("--");
  const [honeyMsg, setHoneyMsg] = useState("");
  const block  = useHardBlock();
  const nav    = useNavigate();
  const start  = useRef(Date.now());
  const clicks = useRef<number[]>([]);
  const reqs   = useRef(0);
  const [rate, setRate] = useState("--");

  useEffect(() => {
    const h = () => { clicks.current.push(Date.now()); if (clicks.current.length > 20) clicks.current.shift(); reqs.current++; };
    document.addEventListener("click", h);
    const iv = setInterval(() => {
      const e = (Date.now() - start.current) / 1000;
      setRate(e > 0 ? (reqs.current / e).toFixed(2) : "--");
    }, 500);
    return () => { document.removeEventListener("click", h); clearInterval(iv); };
  }, []);

  async function pingAction(action: string) {
    if (!token) return;
    const iv = clicks.current.length >= 2
      ? clicks.current.slice(1).map((t, i) => t - clicks.current[i])
      : [200, 300];
    try {
      const r = await fetch("/api/action", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_type: action,
          click_payload: {
            click_intervals: iv.slice(-10),
            session_duration_ms: Date.now() - start.current,
            request_rate_per_sec: parseFloat(rate) || 1,
          },
        }),
      });
      if (r.status === 401) { localStorage.clear(); nav("/app/login"); return; }
      if (r.status === 403) { const d = await r.json(); if (d.banned) block(); return; }
      const d = await r.json();
      if (d.score != null) setScore(d.score.toFixed(4));
      if (!d.allowed) block();
    } catch {}
  }

  async function triggerHoneytoken() {
    setHoneyMsg("Accessing db_config.json...");
    try {
      const r = await fetch("/api/honeytoken", { method: "POST", credentials: "include" });
      if (r.status === 403) { block(); return; }
      setHoneyMsg("Honeytoken event dispatched to SOC.");
    } catch { setHoneyMsg("Server error."); }
  }

  return (
    <div style={{ padding: "24px 24px 0", maxWidth: 900, margin: "0 auto" }}>
      {/* Tab bar */}
      <div style={{ display: "flex", marginBottom: "-1px", borderBottom: "1px solid var(--bd)" }}>
        <button style={tabStyle(tab === "overview")}      onClick={() => { setTab("overview");      pingAction("view_balance"); }}>
          Overview
        </button>
        <button style={tabStyle(tab === "transactions")}  onClick={() => { setTab("transactions");  pingAction("view_balance"); }}>
          Transactions
        </button>
        <button style={tabStyle(tab === "statements")}    onClick={() => { setTab("statements");    pingAction("view_balance"); }}>
          Statements
        </button>
        {/* Admin Controls tab -- only rendered for admin_user */}
        {isAdmin && (
          <button style={tabStyle(tab === "admin", true)} onClick={() => { setTab("admin"); pingAction("admin_login"); }}>
            Admin Controls
          </button>
        )}
      </div>

      <div style={{ paddingTop: 20 }}>
        {/* ── Overview ── */}
        {tab === "overview" && (
          <>
            <div style={card()}>
              <h2 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--mu)", marginBottom: 14 }}>
                &#127968; Welcome, {uname} [{role}]
              </h2>
              <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                {[
                  ["Total AUM", "$4,821,300"],
                  ["YTD Return", "+8.42%"],
                  ["Open Positions", "14"],
                  ["Cash Balance", "$312,500"],
                ].map(([lbl, val]) => (
                  <div key={lbl} style={{
                    background: "var(--bg)", border: "1px solid var(--bd)",
                    borderRadius: 8, padding: "12px 20px", minWidth: 130,
                  }}>
                    <div style={{ fontSize: 10, color: "var(--mu)", marginBottom: 4 }}>{lbl}</div>
                    <div style={{ fontSize: 20, fontWeight: 700, color: "var(--ac)" }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>
            <div style={card()}>
              <h2 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--mu)", marginBottom: 12 }}>
                &#128200; Session Intelligence
              </h2>
              <p style={{ fontSize: 12, color: "var(--mu)", lineHeight: 1.85 }}>
                Req/s: <span style={{ color: "var(--ac)", fontFamily: "monospace" }}>{rate}</span>
                &nbsp;|&nbsp; Anomaly Score: <span style={{ color: score >= "0.85" ? "var(--dr)" : "var(--ac)", fontFamily: "monospace" }}>{score}</span>
              </p>
            </div>
          </>
        )}

        {/* ── Transactions ── */}
        {tab === "transactions" && (
          <div style={card()}>
            <h2 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--mu)", marginBottom: 14 }}>
              &#128203; Recent Transactions
            </h2>
            {[
              ["2024-11-28", "AAPL Buy 50 shares",    "-$9,250.00"],
              ["2024-11-26", "Dividend received",      "+$312.00"],
              ["2024-11-21", "Wire transfer sent",     "-$50,000.00"],
              ["2024-11-14", "Custody fee",            "-$120.00"],
              ["2024-11-01", "MSFT Sell 20 shares",    "+$8,100.00"],
            ].map(([date, desc, amt]) => (
              <div key={date + desc} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid var(--bd)", fontSize: 13 }}>
                <span style={{ color: "var(--mu)", marginRight: 12 }}>{date}</span>
                <span style={{ flex: 1 }}>{desc}</span>
                <span style={{ color: amt.startsWith("+") ? "var(--ok)" : "var(--dr)", fontFamily: "monospace" }}>{amt}</span>
              </div>
            ))}
            <div style={{ marginTop: 16, display: "flex", gap: 10 }}>
              <button onClick={() => pingAction("wire_transfer")}
                      style={{ background: "var(--ac)", color: "#000" }}>
                Initiate Wire Transfer
              </button>
              <button onClick={() => pingAction("view_balance")}
                      style={{ background: "transparent", border: "1px solid var(--bd)", color: "var(--tx)" }}>
                Refresh
              </button>
            </div>
          </div>
        )}

        {/* ── Statements ── */}
        {tab === "statements" && (
          <div style={card()}>
            <h2 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--mu)", marginBottom: 14 }}>
              &#128196; Account Statements
            </h2>
            {["Q3 2024", "Q2 2024", "Q1 2024", "Q4 2023"].map(period => (
              <div key={period} style={{ display: "flex", alignItems: "center", padding: "8px 0", borderBottom: "1px solid var(--bd)" }}>
                <span style={{ flex: 1, fontSize: 13 }}>{period} Statement</span>
                <button onClick={() => pingAction("view_balance")}
                        style={{ background: "transparent", border: "1px solid var(--bd)", color: "var(--mu)", padding: "3px 10px", fontSize: 11 }}>
                  Download PDF
                </button>
              </div>
            ))}
          </div>
        )}

        {/* ── Admin Controls (admin_user only) ── */}
        {tab === "admin" && isAdmin && (
          <>
            <div style={{ ...card(), borderColor: "var(--wn)" }}>
              <h2 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--wn)", marginBottom: 10 }}>
                &#9888; Admin Controls -- Restricted
              </h2>
              <p style={{ fontSize: 12, color: "var(--mu)", lineHeight: 1.7 }}>
                All actions below are logged and monitored by the security system.
              </p>
            </div>
            <div style={card()}>
              <h2 style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: ".07em", color: "var(--mu)", marginBottom: 14 }}>
                &#128193; Internal Vault
              </h2>
              {["Q4_Report.pdf", "Invoices.csv"].map(name => (
                <div key={name} style={{ display: "flex", alignItems: "center", padding: "8px 0", borderBottom: "1px solid var(--bd)" }}>
                  <span style={{ flex: 1, fontSize: 13 }}>&#128196; {name}</span>
                  <button onClick={() => alert(`Downloading ${name} (simulated).`)}
                          style={{ background: "transparent", border: "1px solid var(--bd)", color: "var(--mu)", padding: "3px 10px", fontSize: 11 }}>
                    Download
                  </button>
                </div>
              ))}
              {/* Honeytoken -- the deceptive bait file */}
              <div style={{ display: "flex", alignItems: "center", padding: "8px 0" }}>
                <span style={{ flex: 1, fontSize: 13, color: "var(--wn)", cursor: "pointer" }}
                      onClick={triggerHoneytoken}>
                  &#9888; db_config.json
                </span>
                <button onClick={triggerHoneytoken}
                        style={{ background: "var(--wn)", color: "#000", padding: "3px 10px", fontSize: 11 }}>
                  Open
                </button>
              </div>
              <p style={{ fontSize: 11, color: "var(--mu)", marginTop: 10 }}>
                &#9888; db_config.json is a monitored honeytoken. Access triggers an immediate SOAR response.
              </p>
              {honeyMsg && (
                <p style={{ fontSize: 12, marginTop: 8, color: "var(--wn)" }}>{honeyMsg}</p>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
