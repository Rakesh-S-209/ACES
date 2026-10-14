import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: "0.0.0.0",
    proxy: {
      // All /api calls forwarded to Python backend
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
      // WebSocket forwarding
      "/ws": {
        target: "ws://127.0.0.1:8000",
        ws: true,
        changeOrigin: true,
      },
    },
  },
  // React Router handles /app/* client-side -- always serve index.html
  // for unknown paths so the SPA router can take over on page refresh.
  preview: {
    port: 3000,
    host: "0.0.0.0",
  },
});
