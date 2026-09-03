import { test as setup, expect } from "@playwright/test";

const TOKEN_KEY = "mxcsec_token";
const AUTH_FILE = "e2e/.auth/user.json";

/**
 * One-time login. Credentials come from env:
 *   E2E_USERNAME (default "admin"), E2E_PASSWORD (required).
 * Run with: E2E_PASSWORD='...' pnpm test:e2e
 */
setup("authenticate", async ({ page }) => {
  const username = process.env.E2E_USERNAME || "admin";
  const password = process.env.E2E_PASSWORD;
  if (!password) {
    throw new Error(
      "E2E_PASSWORD is not set. Run the suite with the password in the env, e.g.: E2E_PASSWORD='...' pnpm test:e2e",
    );
  }

  await page.goto("/login");
  await page.getByPlaceholder("请输入用户名").fill(username);
  await page.getByPlaceholder("请输入密码").fill(password);
  await page.locator('button[type="submit"]').click();

  // Login redirects authed users to /dashboard.
  await page.waitForURL("**/dashboard", { timeout: 15_000 });

  // The JWT must have been persisted to localStorage by the login form.
  const token = await page.evaluate((key) => localStorage.getItem(key), TOKEN_KEY);
  expect(token, "mxcsec_token should be present in localStorage after login").toBeTruthy();

  await page.context().storageState({ path: AUTH_FILE });
});
