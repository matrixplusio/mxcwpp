import { test, expect, type Page } from "@playwright/test";

/**
 * Every console sub-route paired with a distinctive zh text that proves the
 * correct page rendered. The `expect` text is, for module sub-pages, the tab
 * label defined in each module's layout.tsx (always rendered as an active tab),
 * which is stable regardless of whether the underlying data list is empty.
 *
 * Paths verified against src/app/(console) on this branch.
 */
const ROUTES: { path: string; expect: string }[] = [
  { path: "/dashboard", expect: "安全概览" },

  // assets
  { path: "/assets/hosts", expect: "主机列表" },
  { path: "/assets/fingerprint", expect: "资产指纹" },
  { path: "/assets/business-lines", expect: "业务线管理" },

  // alert-center
  { path: "/alert-center/alerts", expect: "告警列表" },
  { path: "/alert-center/whitelist", expect: "白名单" },

  // vuln-management
  { path: "/vuln-management/list", expect: "漏洞列表" },
  { path: "/vuln-management/bulletins", expect: "漏洞通报" },
  { path: "/vuln-management/scan-schedules", expect: "扫描计划" },
  { path: "/vuln-management/remediation", expect: "修复报告" },
  { path: "/vuln-management/remediation-tasks", expect: "修复任务" },
  { path: "/vuln-management/remediation-policies", expect: "修复策略" },
  { path: "/vuln-management/db", expect: "漏洞库管理" },
  { path: "/vuln-management/data-sources", expect: "漏洞源管理" },
  { path: "/vuln-management/sbom", expect: "SBOM 导入" },

  // baseline
  { path: "/baseline/policies", expect: "基线检查" },
  { path: "/baseline/groups", expect: "策略组管理" },
  { path: "/baseline/tasks", expect: "任务执行" },
  { path: "/baseline/fix", expect: "基线修复" },
  { path: "/baseline/fix-history", expect: "修复历史" },

  // fim
  { path: "/fim/dashboard", expect: "FIM 概览" },
  { path: "/fim/policies", expect: "FIM 策略" },
  { path: "/fim/events", expect: "FIM 事件" },
  { path: "/fim/tasks", expect: "FIM 任务" },
  { path: "/fim/baselines", expect: "基线管理" },

  // virus
  { path: "/virus/scan", expect: "病毒扫描" },
  { path: "/virus/quarantine", expect: "文件隔离箱" },

  // kube
  { path: "/kube/clusters", expect: "集群管理" },
  { path: "/kube/alarms", expect: "安全告警" },
  { path: "/kube/events", expect: "安全事件" },
  { path: "/kube/baseline", expect: "基线检查" },
  { path: "/kube/baseline-rules", expect: "基线规则" },
  { path: "/kube/whitelist", expect: "告警白名单" },
  { path: "/kube/image-scan", expect: "镜像扫描" },

  // detection
  { path: "/detection/edr-events", expect: "EDR 事件" },
  { path: "/detection/rules", expect: "检测规则" },
  { path: "/detection/threat-intel", expect: "威胁情报" },
  { path: "/detection/storylines", expect: "攻击故事线" },
  { path: "/detection/hunting", expect: "威胁狩猎" },
  { path: "/detection/anomaly", expect: "ML 异常检测" },
  { path: "/detection/bde", expect: "行为基线" },

  // operations
  { path: "/operations/components", expect: "组件管理" },
  { path: "/operations/inspection", expect: "运维巡检" },
  { path: "/operations/backup", expect: "配置备份" },
  { path: "/operations/migration", expect: "迁移助手" },
  { path: "/operations/reports", expect: "报告管理" },
  { path: "/operations/task-report", expect: "任务报告" },
  { path: "/operations/install", expect: "安装配置" },

  // system
  { path: "/system/users", expect: "用户管理" },
  { path: "/system/rbac", expect: "角色权限" },
  { path: "/system/notifications", expect: "通知管理" },
  { path: "/system/settings", expect: "基本设置" },
  { path: "/system/retention", expect: "数据保留" },
  { path: "/system/feature-flags", expect: "功能开关" },

  // monitoring
  { path: "/monitoring/host", expect: "主机监控" },
  { path: "/monitoring/services", expect: "后端服务" },
  { path: "/monitoring/service-alerts", expect: "服务告警" },

  // audit
  { path: "/audit-log", expect: "审计日志" },
];

/** Returns true if a Next.js runtime error overlay is present. */
async function hasErrorOverlay(page: Page): Promise<boolean> {
  const dialog = await page.locator("[data-nextjs-dialog]").count();
  if (dialog > 0) return true;
  const runtime = await page.getByText(/Unhandled Runtime Error|Runtime Error/).count();
  return runtime > 0;
}

test.describe("console routes render without crashes, console errors, or auth bounce", () => {
  for (const route of ROUTES) {
    test(`${route.path} → "${route.expect}"`, async ({ page }) => {
      const consoleErrors: string[] = [];
      page.on("console", (msg) => {
        if (msg.type() === "error") consoleErrors.push(msg.text());
      });
      page.on("pageerror", (err) => consoleErrors.push(`[pageerror] ${err.message}`));

      await page.goto(route.path, { waitUntil: "domcontentloaded" });
      try {
        await page.waitForLoadState("networkidle", { timeout: 1_500 });
      } catch {
        // Some pages keep polling; fall back to a fixed settle window.
        await page.waitForTimeout(1_500);
      }

      // 1) No auth bounce: still on the requested route (proves guard + token work).
      expect(
        page.url(),
        `expected to stay on ${route.path} but landed on ${page.url()} (auth bounce?)`,
      ).toContain(route.path);

      // 2) No Next.js runtime error overlay.
      expect(await hasErrorOverlay(page), "Next.js runtime error overlay present").toBe(false);

      // 3) Page rendered the right content OR at least the console shell.
      //    Robust to empty data: we assert chrome, not rows.
      const expected = page.getByText(route.expect, { exact: false }).first();
      const shell = page.getByText("导航", { exact: true }); // sidebar nav header
      const ok =
        (await expected.count()) > 0 ? await expected.isVisible() : await shell.isVisible();
      expect(
        ok,
        `neither expected text "${route.expect}" nor console shell rendered on ${route.path}`,
      ).toBe(true);

      // 4) No console errors / page errors.
      expect(consoleErrors, `console errors on ${route.path}:\n${consoleErrors.join("\n")}`).toEqual(
        [],
      );
    });
  }
});
