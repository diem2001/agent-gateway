import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    // Process security probes sample /proc on short intervals; many parallel
    // gateway/runtime children make their timing assertions unreliable.
    maxWorkers: 2,
  },
});
