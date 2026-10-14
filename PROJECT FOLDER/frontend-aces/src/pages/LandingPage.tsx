import React from "react";
import { Link } from "react-router-dom";

// Public landing page -- no auth check, no SOAR trigger.
// Looks like a standard corporate site to any visitor.

const hero: React.CSSProperties = {
  textAlign: "center", padding: "80px 24px 60px",
  maxWidth: 720, margin: "0 auto",
};
const tagline: React.CSSProperties = {
  fontSize: 36, fontWeight: 800, color: "var(--tx)", lineHeight: 1.25, marginBottom: 16,
};
const sub: React.CSSProperties = {
  fontSize: 15, color: "var(--mu)", lineHeight: 1.75, marginBottom: 36,
};
const ctaRow: React.CSSProperties = {
  display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap",
};
const btnPrimary: React.CSSProperties = {
  background: "var(--ac)", color: "#000", padding: "11px 28px",
  borderRadius: 8, fontWeight: 700, fontSize: 14, textDecoration: "none",
  display: "inline-block",
};
const btnSecondary: React.CSSProperties = {
  background: "transparent", color: "var(--ac)", padding: "11px 28px",
  borderRadius: 8, fontWeight: 700, fontSize: 14, textDecoration: "none",
  border: "1px solid var(--ac)", display: "inline-block",
};
const grid: React.CSSProperties = {
  display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))",
  gap: 16, maxWidth: 860, margin: "0 auto 60px", padding: "0 24px",
};
const featureCard: React.CSSProperties = {
  background: "var(--s)", border: "1px solid var(--bd)", borderRadius: 10,
  padding: 20,
};
const fTitle: React.CSSProperties = {
  fontSize: 13, fontWeight: 700, color: "var(--tx)", marginBottom: 6,
};
const fBody: React.CSSProperties = {
  fontSize: 12, color: "var(--mu)", lineHeight: 1.7,
};

const features = [
  { icon: "&#128200;", title: "Portfolio Analytics",
    body: "Real-time performance dashboards across all asset classes." },
  { icon: "&#128176;", title: "Digital Securities",
    body: "Compliant issuance and custody of tokenised assets." },
  { icon: "&#127759;", title: "Global Markets",
    body: "Access institutional-grade execution in 40+ markets." },
  { icon: "&#128274;", title: "Institutional Security",
    body: "SOC-2 Type II certified infrastructure and zero-trust access." },
];

export default function LandingPage() {
  return (
    <>
      <div style={hero}>
        <h1 style={tagline}>
          Boutique Investment Management<br />for a Digital World
        </h1>
        <p style={sub}>
          NorthStar Capital partners with institutional investors and family offices
          to navigate alternative assets and digital securities with precision.
        </p>
        <div style={ctaRow}>
          <Link to="/app/login"  style={btnPrimary}>Sign In to Portal</Link>
          <Link to="/app/signup" style={btnSecondary}>Open an Account</Link>
        </div>
      </div>

      <div style={grid}>
        {features.map(f => (
          <div key={f.title} style={featureCard}>
            <div style={{ fontSize: 22, marginBottom: 8 }}
                 dangerouslySetInnerHTML={{ __html: f.icon }} />
            <div style={fTitle}>{f.title}</div>
            <div style={fBody}>{f.body}</div>
          </div>
        ))}
      </div>

      <footer style={{ textAlign: "center", fontSize: 11, color: "#2e3a48", paddingBottom: 32 }}>
        &copy; 2024 NorthStar Capital Ltd. Regulated by the FCA. All rights reserved.
      </footer>
    </>
  );
}
