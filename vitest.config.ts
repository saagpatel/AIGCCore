import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    include: [
      "src/**/*.test.{ts,tsx}",
      "src/**/*.spec.{ts,tsx}",
      "tests/unit/**/*.test.{ts,tsx,js,mjs,cjs}",
      "tests/unit/**/*.spec.{ts,tsx,js,mjs,cjs}",
    ],
    exclude: [
      "tests/ui/**",
      "tests/perf/**",
      "node_modules/**",
      "dist/**",
      "target/**",
      "src-tauri/target/**",
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      reportsDirectory: "coverage",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/**/*.spec.{ts,tsx}"],
    },
  },
});
