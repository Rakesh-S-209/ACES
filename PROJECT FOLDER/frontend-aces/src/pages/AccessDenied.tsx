import React from "react";

export default function AccessDenied() {
  return (
    <div style={{
      position:"fixed", inset:0, background:"#080304",
      display:"flex", flexDirection:"column",
      alignItems:"center", justifyContent:"center",
      zIndex: 9999,
    }}>
      <div style={{fontSize:64, marginBottom:16}}>&#128683;</div>
      <h1 style={{fontSize:26, fontWeight:700, color:"var(--dr)", marginBottom:8}}>
        Access Permanently Denied
      </h1>
      <p style={{color:"var(--mu)", fontSize:13, marginBottom:6}}>
        Your IP has been flagged and blacklisted by the security system.
      </p>
      <p style={{color:"var(--dr)", fontSize:13}}>
        Session terminated. All credentials have been invalidated.
      </p>
      <p style={{marginTop:24, fontSize:11, color:"#3a2020"}}>
        A.C.E.S. Automated Cybersecurity &amp; Deception System
      </p>
    </div>
  );
}
