import React from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";

const hdr: React.CSSProperties = {
  background: "var(--s)", borderBottom: "1px solid var(--bd)",
  padding: "10px 24px", display: "flex", alignItems: "center", gap: "16px",
};
const logo: React.CSSProperties  = { fontSize: 17, fontWeight: 700, color: "var(--ac)" };
const lnk: React.CSSProperties   = { color: "var(--mu)", fontSize: 13, textDecoration: "none" };
const act: React.CSSProperties   = { color: "var(--tx)", fontSize: 13, textDecoration: "none" };
const logoBtnStyle: React.CSSProperties = {
  background: "transparent", border: "1px solid var(--bd)",
  color: "var(--mu)", padding: "4px 10px", fontSize: 11,
  borderRadius: 6, cursor: "pointer",
};

export default function Nav() {
  const nav   = useNavigate();
  const loc   = useLocation();
  const token = localStorage.getItem("aces_token");
  const role  = localStorage.getItem("aces_role");
  const user  = localStorage.getItem("aces_user");

  const isSOC = loc.pathname.startsWith("/app/soc-board");

  function a(path: string): React.CSSProperties {
    return loc.pathname === path ? act : lnk;
  }

  async function logout() {
    const t = localStorage.getItem("aces_token");
    if (t) {
      await fetch("/api/logout", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: t }),
      }).catch(() => {});
    }
    localStorage.clear();
    nav("/app/login");
  }

  // SOC board gets a stripped-down header (no corporate nav)
  if (isSOC) {
    return (
      <header style={{ ...hdr, background: "#060a0f", borderColor: "#21262d" }}>
        <span style={{ ...logo, color: "var(--dr)", fontSize: 15 }}>
          &#9650; A.C.E.S. SOC Board
        </span>
        <span style={{ fontSize: 10, color: "var(--mu)", marginLeft: 4 }}>
          RESTRICTED
        </span>
        {token && (
          <>
            <span style={{ marginLeft: "auto", fontSize: 11, color: "var(--mu)" }}>
              {user} [{role}]
            </span>
            <button onClick={logout} style={logoBtnStyle}>Logout</button>
          </>
        )}
      </header>
    );
  }

  return (
    <header style={hdr}>
      <Link to="/app/home" style={logo as React.CSSProperties}>
        &#9632; NorthStar Capital
      </Link>

      <Link to="/app/home"  style={a("/app/home")}>Home</Link>

      {token && (
        <Link to="/app/dashboard" style={a("/app/dashboard")}>
          My Portal
        </Link>
      )}

      {/* SOC link is only visible to admins -- completely hidden from others */}
      {token && role === "Admin" && (
        <Link to="/app/soc-board" style={{ ...a("/app/soc-board"), color: "var(--dr)" }}>
          SOC Board
        </Link>
      )}

      <span style={{ marginLeft: "auto" }} />

      {token ? (
        <>
          <span style={{ fontSize: 11, color: "var(--mu)" }}>
            {user} [{role}]
          </span>
          <button onClick={logout} style={logoBtnStyle}>Logout</button>
        </>
      ) : (
        <>
          <Link to="/app/login"  style={a("/app/login")}>Sign In</Link>
          <Link to="/app/signup" style={{
            ...a("/app/signup"),
            background: "var(--ac)", color: "#000",
            padding: "5px 14px", borderRadius: 6, fontWeight: 600,
          }}>
            Sign Up
          </Link>
        </>
      )}
    </header>
  );
}
