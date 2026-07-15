import { defineConfig } from "vitest/config";

// Pure-logic tests only. The dashboard has no component-test infrastructure
// (no @testing-library), which is why picker logic lives in lib/ as pure
// functions rather than inline in components.
export default defineConfig({
  test: {
    environment: "node",
    include: ["app/**/*.test.ts"],
  },
});
