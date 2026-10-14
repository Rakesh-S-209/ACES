import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import LandingPage   from "./pages/LandingPage";
import LoginPage     from "./pages/LoginPage";
import SignUpPage    from "./pages/SignUpPage";
import DashboardPage from "./pages/DashboardPage";
import SOCBoard      from "./pages/SOCBoard";
import AccessDenied  from "./pages/AccessDenied";
import ForbiddenPage from "./pages/ForbiddenPage";
import Nav           from "./components/Nav";

// Requires a valid auth token in localStorage
function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem("aces_token");
  if (!token) return <Navigate to="/app/login" replace />;
  return <>{children}</>;
}

// Requires Admin role -- renders hard 403 inline, NO redirect loop
function RequireAdmin({ children }: { children: React.ReactNode }) {
  const role = localStorage.getItem("aces_role");
  if (role !== "Admin") return <ForbiddenPage />;
  return <>{children}</>;
}

export default function App() {
  return (
    <>
      <Nav />
      <Routes>
        {/* Root redirect */}
        <Route path="/"              element={<Navigate to="/app/home" replace />} />

        {/* Public routes -- NO auth check, NO SOAR trigger */}
        <Route path="/app/home"      element={<LandingPage />} />
        <Route path="/app/login"     element={<LoginPage />} />
        <Route path="/app/signup"    element={<SignUpPage />} />

        {/* Protected unified portal (all authenticated users) */}
        <Route path="/app/dashboard" element={
          <RequireAuth><DashboardPage /></RequireAuth>
        } />

        {/* SOC board -- Admin only, hard 403 for anyone else */}
        <Route path="/app/soc-board" element={
          <RequireAuth><RequireAdmin><SOCBoard /></RequireAdmin></RequireAuth>
        } />

        {/* Utility pages */}
        <Route path="/access-denied" element={<AccessDenied />} />
        <Route path="/403"           element={<ForbiddenPage />} />

        {/* Legacy route aliases kept for backward compatibility */}
        <Route path="/login"         element={<Navigate to="/app/login" replace />} />
        <Route path="/home"          element={<Navigate to="/app/dashboard" replace />} />
        <Route path="/soc-dashboard" element={<Navigate to="/app/soc-board" replace />} />

        {/* Catch-all */}
        <Route path="*"              element={<Navigate to="/app/home" replace />} />
      </Routes>
    </>
  );
}
