import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

// Public sign-up page -- no SOAR trigger, no ban check.

const card: React.CSSProperties = {
  background: "var(--s)", border: "1px solid var(--bd)", borderRadius: 10,
  padding: 28, maxWidth: 400, margin: "60px auto",
};

export default function SignUpPage() {
  const [full,  setFull]  = useState("");
  const [email, setEmail] = useState("");
  const [pass,  setPass]  = useState("");
  const [msg,   setMsg]   = useState("");
  const [ok,    setOk]    = useState(false);
  const nav = useNavigate();

  async function submit() {
    if (!full.trim() || !email.trim() || !pass) {
      setMsg("Please fill in all fields."); return;
    }
    setMsg("");
    // In this demo the backend has fixed accounts; show a success message.
    setOk(true);
    setMsg("Account request submitted. Our team will be in touch shortly.");
    setTimeout(() => nav("/app/login"), 3000);
  }

  return (
    <div style={card}>
      <h2 style={{ fontSize: 13, textTransform: "uppercase", letterSpacing: ".06em",
                   color: "var(--mu)", marginBottom: 20 }}>
        &#127760; Open an Account
      </h2>

      <label style={{ fontSize: 11, color: "var(--mu)", marginBottom: 4, display: "block" }}>
        Full Name
      </label>
      <input value={full} onChange={e => setFull(e.target.value)} placeholder="Jane Smith" />

      <label style={{ fontSize: 11, color: "var(--mu)", marginBottom: 4, display: "block" }}>
        Work Email
      </label>
      <input type="email" value={email} onChange={e => setEmail(e.target.value)}
             placeholder="jane@institution.com" />

      <label style={{ fontSize: 11, color: "var(--mu)", marginBottom: 4, display: "block" }}>
        Create Password
      </label>
      <input type="password" value={pass} onChange={e => setPass(e.target.value)}
             placeholder="Min. 8 characters"
             onKeyDown={e => e.key === "Enter" && submit()} />

      <button onClick={submit} disabled={ok}
              style={{ width: "100%", background: ok ? "var(--ok)" : "var(--ac)",
                       color: "#000", marginTop: 4 }}>
        {ok ? "Submitted!" : "Create Account"}
      </button>

      {msg && (
        <p style={{ fontSize: 12, marginTop: 10,
                    color: ok ? "var(--ok)" : "var(--dr)" }}>
          {msg}
        </p>
      )}
      <p style={{ fontSize: 11, color: "var(--mu)", marginTop: 16 }}>
        Already have access?{" "}
        <Link to="/app/login" style={{ color: "var(--ac)" }}>Sign In</Link>
      </p>
    </div>
  );
}
