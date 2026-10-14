import React from "react";
import { Link } from "react-router-dom";

// Hard 403 Forbidden page.
// Rendered INLINE for unauthorized /app/soc-board access -- no redirect loop.

export default function ForbiddenPage() {
  return (
    <div style={{
      minHeight: "80vh", display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      background: "var(--bg)", padding: 24,
    }}>
      <div style={{ fontSize: 56, marginBottom: 16 }}>&#128683;</div>
      <h1 style={{ fontSize: 28, fontWeight: 800, color: "var(--dr)", marginBottom: 8 }}>
        403 Forbidden
      </h1>
      <p style={{ fontSize: 14, color: "var(--mu)", marginBottom: 6, textAlign: "center" }}>
        You do not have permission to access this resource.
      </p>
      <p style={{ fontSize: 12, color: "#3a2020", marginBottom: 28, textAlign: "center" }}>
        This access attempt has been logged.
      </p>
      <Link to="/app/dashboard" style={{
        background: "transparent", border: "1px solid var(--bd)",
        color: "var(--mu)", padding: "8px 20px", borderRadius: 6,
        fontSize: 13, textDecoration: "none",
      }}>
        Return to Portal
      </Link>
    </div>
  );
}
