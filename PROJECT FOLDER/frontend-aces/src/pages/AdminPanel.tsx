import React, { useState } from "react";
import { useHardBlock } from "../hooks/useAuth";

export default function AdminPanel() {
  const block = useHardBlock();
  const [msg, setMsg] = useState("");
  const [msgCls, setMsgCls] = useState("");

  async function openHoneytoken() {
    setMsg("Accessing db_config.json...");
    setMsgCls("");
    try {
      const r = await fetch("/api/honeytoken", { method:"POST" });
      if (r.status === 403) {
        setMsg("BLOCKED: Honeytoken triggered. Your IP has been banned.");
        setMsgCls("dr");
        block();
      } else {
        const d = await r.json();
        setMsg(d.triggered ? "Honeytoken event sent." : "Response received.");
      }
    } catch { setMsg("Server error."); }
  }

  function fakeDownload(name: string) {
    setMsg(`Downloading ${name} (simulated).`);
    setTimeout(() => setMsg(""), 3000);
  }

  const card: React.CSSProperties = {
    background:"var(--s)", border:"1px solid var(--bd)", borderRadius:10,
    padding:20, marginBottom:20,
  };
  const warnCard: React.CSSProperties = {
    ...card, borderColor:"var(--wn)",
  };
  const fileRow: React.CSSProperties = {
    display:"flex", alignItems:"center", padding:"8px 0",
    borderBottom:"1px solid var(--bd)",
  };

  return (
    <div style={{padding:"28px 24px", maxWidth:800, margin:"0 auto"}}>
      <div style={warnCard}>
        <h2 style={{fontSize:13,textTransform:"uppercase",letterSpacing:".06em",color:"var(--wn)",marginBottom:10}}>
          &#9888; Administrator Panel -- Restricted
        </h2>
        <p style={{fontSize:12,color:"var(--mu)",lineHeight:1.7}}>
          All actions in this panel are logged and monitored. Unauthorised access is a criminal offence.
        </p>
      </div>

      <div style={card}>
        <h2 style={{fontSize:13,textTransform:"uppercase",letterSpacing:".06em",color:"var(--mu)",marginBottom:14}}>
          &#128193; Internal Vault
        </h2>

        <div style={fileRow}>
          <span style={{marginRight:10}}>&#128196;</span>
          <span style={{flex:1}}>Q4_Report.pdf</span>
          <button onClick={()=>fakeDownload("Q4_Report.pdf")}
                  style={{background:"transparent",border:"1px solid var(--bd)",color:"var(--mu)",padding:"4px 10px",fontSize:11}}>
            Download
          </button>
        </div>

        <div style={fileRow}>
          <span style={{marginRight:10}}>&#128202;</span>
          <span style={{flex:1}}>Invoices.csv</span>
          <button onClick={()=>fakeDownload("Invoices.csv")}
                  style={{background:"transparent",border:"1px solid var(--bd)",color:"var(--mu)",padding:"4px 10px",fontSize:11}}>
            Download
          </button>
        </div>

        <div style={{...fileRow, borderBottom:"none"}}>
          <span style={{marginRight:10}}>&#9888;</span>
          <span style={{flex:1,color:"var(--wn)",cursor:"pointer"}} onClick={openHoneytoken}>
            db_config.json
          </span>
          <button onClick={openHoneytoken}
                  style={{background:"var(--wn)",color:"#000",padding:"4px 10px",fontSize:11}}>
            Open
          </button>
        </div>

        <p style={{fontSize:11,color:"var(--mu)",marginTop:10}}>
          &#9888; Access to db_config.json is a monitored honeytoken. Opening it triggers an immediate security response.
        </p>
        {msg && <p style={{fontSize:12,marginTop:8,color:msgCls==="dr"?"var(--dr)":"var(--wn)"}}>{msg}</p>}
      </div>
    </div>
  );
}
