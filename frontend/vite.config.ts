import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      // ws:true 让 Vite 转发 WebSocket upgrade (/api/ws/events)
      "/api": { target: "http://localhost:8001", ws: true },
      "/health": { target: "http://localhost:8001", ws: true },
    },
  },
  build: {
    chunkSizeWarningLimit: 700,
    rolldownOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules")) {
            if (id.includes("react-router") || /[\\/]react[\\/]|[\\/]react-dom[\\/]/.test(id)) {
              return "react-vendor";
            }
            if (id.includes("antd") || id.includes("@ant-design")) {
              return "antd-vendor";
            }
            if (id.includes("recharts") || id.includes("dayjs")) {
              return "chart-vendor";
            }
          }
        },
      },
    },
  },
});
