import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    // Enable globals (optional - allows using describe, it, expect without imports)
    globals: true,

    // Test environment (node is default, use 'jsdom' if you need browser APIs)
    environment: "node",

    // Coverage configuration
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html", "lcov"],
      exclude: [
        "node_modules/",
        "dist/",
        "**/*.config.ts",
        "**/*.d.ts",
        "**/*.test.ts",
        "**/*.spec.ts",
        "src/types/**", // Type definitions only
        "src/index.ts", // Main entry point - just re-exports
        "src/string/caseConversion/index.ts", // Just re-exports
      ],
      // Set coverage thresholds (adjust as needed)
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },

    // Include test files (co-located in src)
    include: ["src/**/*.{test,spec}.{js,ts}"],

    // Exclude files
    exclude: ["node_modules", "dist", ".idea", ".git", ".cache"],

    // Watch mode options for incremental testing
    watch: true,

    // Pool options for parallel test execution
    pool: "threads",

    // Test timeout
    testTimeout: 10000,

    // Reporter configuration
    reporters: ["default"],

    // Isolate environment for each test file
    isolate: true,
  },
})
