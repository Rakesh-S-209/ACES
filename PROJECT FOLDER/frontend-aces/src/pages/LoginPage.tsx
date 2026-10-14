import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";

// Single unified login for ALL users including admin_user.
// No "Admin Login" button -- admin access is completely stealthy.

const card: React.CSSProperties = {
  background: "var(--s)", border: "1px solid var(--bd)", borderRadius: 10,
  padding: 28, maxWidth: 380, margin: "60px auto",
};

export default function LoginPage() {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err,  setErr]  = useState("");
  const [busy, setBusy] = useState(false);
  const nav = useNavigate();

  async function login() {
    if (!user.trim() || !pass) { setErr("Please enter your username and password."); return; }
    setErr(""); setBusy(true);
    try {
      const r = await fetch("/api/login", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user.trim(), password: pass }),
      });
      const d = await r.json();
      if (r.status !== 200 || d.error) {
        setErr("Invalid username or password.");
        setBusy(false);
        return;
      }
      localStorage.setItem("aces_token", d.token);
      localStorage.setItem("aces_role",  d.role);
      localStorage.setItem("aces_user",  d.username);
      // All users go to dashboard -- admin sees extra tab there
      nav("/app/dashboard", { replace: true });
    } catch {
      setErr("Server unreachable. Check that run.py is running.");
      setBusy(false);
    }
  }

  return (
    <div style={card}>
      <h2 style={{ fontSize: 13, textTransform: "uppercase", letterSpacing: ".06em",
                   color: "var(--mu)", marginBottom: 20 }}>
        &#128274; Sign In
      </h2>
      <input
        value={user} onChange={e => setUser(e.target.value)}
        placeholder="Username" autoComplete="username" autoFocus
      />
      <input
        type="password" value={pass} onChange={e => setPass(e.target.value)}
        placeholder="Password" autoComplete="current-password"
        onKeyDown={e => e.key === "Enter" && login()}
      />
      <button
        onClick={login} disabled={busy}
        style={{ width: "100%", background: "var(--ac)", color: "#000",
                 marginTop: 4, opacity: busy ? 0.7 : 1 }}>
        {busy ? "Signing in..." : "Sign In"}
      </button>
      {err && (
        <p style={{ color: "var(--dr)", fontSize: 12, marginTop: 10 }}>{err}</p>
      )}
      <p style={{ fontSize: 11, color: "var(--mu)", marginTop: 16, lineHeight: 1.7 }}>
        Don&apos;t have an account?{" "}
        <Link to="/app/signup" style={{ color: "var(--ac)" }}>Sign Up</Link>
      </p>
      <p style={{ fontSize: 10, color: "#2e3a48", marginTop: 14, lineHeight: 1.7 }}>
        Demo: client_user / ClientPass1! &nbsp; eng_user / EngPass2!
      </p>
    </div>
  );
}
