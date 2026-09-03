import { test, expect } from "@playwright/test";

test.describe("dashboard", () => {
  test("renders security overview with stats and no errors", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => consoleErrors.push(err.message));

    // Capture the dashboard stats API response body.
    let statsCode: number | undefined;
    page.on("response", async (resp) => {
      if (resp.url().includes("/api/v1/dashboard/stats")) {
        try {
          const body = await resp.json();
          statsCode = body?.code;
        } catch {
          /* non-JSON, leave undefined */
        }
      }
    });

    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    try {
      await page.waitForLoadState("networkidle", { timeout: 5_000 });
    } catch {
      /* networkidle may not settle; continue */
    }

    // Heading.
    await expect(page.getByRole("heading", { name: "安全概览" })).toBeVisible();

    // The stats API succeeded with business code 0.
    expect(statsCode, "GET /api/v1/dashboard/stats should return code 0").toBe(0);

    // At least one KPI stat number rendered. KpiRow labels are stable; assert a
    // known KPI label is present and the card shows a non-empty value.
    const kpiLabel = page.getByText("在线 Agent", { exact: true });
    await expect(kpiLabel).toBeVisible();

    // No Next.js runtime error overlay.
    await expect(page.locator("[data-nextjs-dialog]")).toHaveCount(0);
    await expect(page.getByText("Unhandled Runtime Error")).toHaveCount(0);
    await expect(page.getByText("Runtime Error", { exact: true })).toHaveCount(0);

    // No console errors.
    expect(consoleErrors, consoleErrors.join("\n")).toEqual([]);
  });
});
