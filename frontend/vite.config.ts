import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api": "http://localhost:8001",
      "/health": "http://localhost:8001",
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
