import React, { useEffect, useRef, useState } from "react";
import { useHardBlock } from "../hooks/useAuth";

const card = (extra?: React.CSSProperties): React.CSSProperties => ({
  background:"var(--s)", border:"1px solid var(--bd)", borderRadius:10,
  padding:20, marginBottom:20, ...extra,
});

export default function HomePage() {
  const block = useHardBlock();
  const [score, setScore] = useState("--");
  const clicks = useRef<number[]>([]);
  const reqCount = useRef(0);
  const start = useRef(Date.now());
  const [dur, setDur] = useState("0");
  const [rate, setRate] = useState("--");

  useEffect(() => {
    const handler = () => { clicks.current.push(Date.now()); if(clicks.current.length>20) clicks.current.shift(); reqCount.current++; };
    document.addEventListener("click", handler);
    const iv = setInterval(() => {
      setDur(String(Date.now()-start.current));
      const e = (Date.now()-start.current)/1000;
      setRate(e>0?(reqCount.current/e).toFixed(2):"--");
    }, 500);
    return () => { document.removeEventListener("click", handler); clearInterval(iv); };
  }, []);

  async function pingAction(action: string) {
    const token = localStorage.getItem("aces_token");
    if (!token) return;
    const iv = clicks.current.length >= 2
      ? clicks.current.slice(1).map((t,i)=>t-clicks.current[i])
      : [200,300];
    try {
      const r = await fetch("/api/action", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ session_id: token.slice(0,12), action_type: action,
          click_payload:{ click_intervals: iv.slice(-10), session_duration_ms: Date.now()-start.current, request_rate_per_sec: parseFloat(rate)||1 } }),
      });
      if (r.status === 403) { const d = await r.json(); if(d.banned) block(); return; }
      const d = await r.json();
      if (d.score != null) setScore(d.score.toFixed(4));
      if (!d.allowed) block();
    } catch {}
  }

  return (
    <div style={{padding:"28px 24px", maxWidth:800, margin:"0 auto"}}>
      <div style={card()}>
        <h2 style={{fontSize:13,textTransform:"uppercase",letterSpacing:".06em",color:"var(--mu)",marginBottom:12}}>
          &#127968; Welcome, {localStorage.getItem("aces_user")} [{localStorage.getItem("aces_role")}]
        </h2>
        <p style={{color:"var(--mu)",lineHeight:1.7}}>Select an action to interact with the portal. Your session behaviour is monitored in real time.</p>
      </div>
      <div style={card()}>
        <h2 style={{fontSize:13,textTransform:"uppercase",letterSpacing:".06em",color:"var(--mu)",marginBottom:12}}>
          &#128200; Session Telemetry
        </h2>
        <p style={{fontSize:12,color:"var(--mu)",lineHeight:1.8}}>
          Session age: <span style={{color:"var(--ac)",fontFamily:"monospace"}}>{dur}</span>ms &nbsp;|&nbsp;
          Req/s: <span style={{color:"var(--ac)",fontFamily:"monospace"}}>{rate}</span> &nbsp;|&nbsp;
          Last score: <span style={{color:"var(--dr)",fontFamily:"monospace"}}>{score}</span>
        </p>
      </div>
      <div style={card()}>
        <h2 style={{fontSize:13,textTransform:"uppercase",letterSpacing:".06em",color:"var(--mu)",marginBottom:12}}>
          &#128206; Portal Actions
        </h2>
        <div style={{display:"flex",gap:10,flexWrap:"wrap"}}>
          <button onClick={()=>pingAction("view_balance")} style={{background:"var(--ac)",color:"#000"}}>View Balance</button>
          <button onClick={()=>pingAction("wire_transfer")} style={{background:"var(--s)",border:"1px solid var(--bd)",color:"var(--tx)"}}>Wire Transfer</button>
        </div>
      </div>
    </div>
  );
}
