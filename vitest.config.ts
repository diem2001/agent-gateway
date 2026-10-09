import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    // The verdict of the process sampler windows (MVP-8139). Its afterEach must run last: leave `sequence.hooks` at the default ("stack").
    setupFiles: ["src/tests/setup/sampler-verdict.ts"],
  },
});
