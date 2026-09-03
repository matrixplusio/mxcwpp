import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright e2e config for the MXCWPP-PLATFORM React console.
 *
 * Credentials are read from env at runtime (never hardcoded):
 *   E2E_USERNAME (default "admin")
 *   E2E_PASSWORD (no default — must be provided)
 * Example: E2E_PASSWORD='...' pnpm test:e2e
 *
 * This config REUSES an already-running dev server at http://localhost:3000.
 * For CI you would add a `webServer` block, e.g.:
 *   webServer: { command: "pnpm dev", url: "http://localhost:3000", reuseExistingServer: true }
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    viewport: { width: 1440, height: 900 },
  },
  projects: [
    // Logs in once and persists storageState for the rest of the suite.
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    {
      name: "chromium",
      dependencies: ["setup"],
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 900 },
        storageState: "e2e/.auth/user.json",
      },
    },
  ],
});
