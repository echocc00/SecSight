import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node", // 只测纯逻辑;组件测试需 jsdom,当前未引入
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
});
