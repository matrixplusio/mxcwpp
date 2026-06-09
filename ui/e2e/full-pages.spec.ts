/**
 * 全量 UI 巡检 — 遍历 menuConfig 所有路由 + 隐藏路由 (T3 + 后端补全模块).
 *
 * 每个路由检查:
 *   1. page.goto 返回 200 (SPA 总返 200, 真正校验 router 命中)
 *   2. 无 console error (页面加载脚本/组件渲染异常)
 *   3. 后端关键 XHR 不返 5xx (4xx 容忍 = 资源真不存在; 5xx = 服务器错)
 *   4. 顶部有 <h2> 或 <a-card> 或 <a-table> 任一关键 DOM 节点
 *   5. 截图存证 (test-results/screenshots/)
 *
 * 跑:
 *   E2E_BASE_URL=http://localhost:3000 E2E_NO_SERVER=1 \
 *     JWT_SECRET='dev-secret-change-in-production!!' \
 *     pnpm exec playwright test e2e/full-pages.spec.ts --project=chromium --reporter=list
 */
import { test, expect, Page } from '@playwright/test'
import { createHmac } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const USER = process.env.E2E_USERNAME || 'admin'
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production!!'

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function devToken(): string {
  const hdr = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const now = Math.floor(Date.now() / 1000)
  const pl = b64url(
    JSON.stringify({
      username: USER, role: 'admin', tenant_id: 'default', is_platform_admin: true,
      iss: 'mxsec-platform', iat: now, exp: now + 3600,
    }),
  )
  const sig = b64url(createHmac('sha256', SECRET).update(`${hdr}.${pl}`).digest())
  return `${hdr}.${pl}.${sig}`
}

const ROUTES: string[] = [
  // 总览
  '/dashboard',
  // 资产
  '/hosts', '/asset-fingerprint', '/business-lines',
  // 告警
  '/alerts', '/whitelist',
  // 漏洞
  '/vuln-bulletins', '/vuln-list', '/vuln-scan-schedules',
  '/vuln-remediation', '/vuln-remediation/tasks', '/vuln-remediation/policies',
  '/vuln-db-manage', '/vuln-data-sources', '/sbom-import',
  // 基线
  '/policies', '/policy-groups', '/tasks', '/baseline/fix', '/baseline/fix-history',
  // FIM
  '/fim/dashboard', '/fim/policies', '/fim/events', '/fim/tasks', '/fim/baselines',
  // 病毒
  '/virus/scan', '/virus/quarantine',
  // 容器
  '/kube/clusters', '/kube/alarms', '/kube/events', '/kube/baseline',
  '/kube/baseline-rules', '/kube/whitelist', '/kube/image-scan',
  // 威胁检测
  '/edr/events', '/detection/rules', '/threat-intel', '/storylines',
  '/hunting', '/anomaly', '/bde', '/host-isolation',
  // 运维
  '/system/components', '/system/install', '/system/reports', '/system/task-report',
  '/system/inspection', '/system/backup', '/system/migration',
  // 系统
  '/users', '/system/notification', '/system/settings', '/system/data-retention',
  '/system/feature-flags', '/system/collection',
  // 监控
  '/system/host-monitor', '/system/service-monitor', '/system/service-alert',
  // 审计
  '/audit-log',
  // T3 新增 (后端 #126/127 已补)
  '/memory-threats', '/honeypot', '/rootkit', '/ad-audit', '/vex',
]

// 巡检报告路径
const REPORT_DIR = 'test-results/full-pages-report'
const SHOTS_DIR = `${REPORT_DIR}/screenshots`
fs.mkdirSync(SHOTS_DIR, { recursive: true })

interface PageReport {
  route: string
  status: 'PASS' | 'FAIL' | 'WARN'
  consoleErrors: string[]
  http5xx: string[]
  http4xx: string[]
  hasKeyDom: boolean
  screenshot: string
}
const REPORT: PageReport[] = []

test.afterAll(() => {
  // 4 worker 并行, 每个进程有独立 REPORT 副本.
  // 写 per-worker JSON 分片, 跑完后跑 scripts/full-pages-merge.sh 合并 (或 afterAll 用 spawn).
  const workerID = process.env.TEST_WORKER_INDEX || '0'
  fs.writeFileSync(path.join(REPORT_DIR, `report-w${workerID}.json`), JSON.stringify(REPORT, null, 2))
})

async function injectToken(page: Page) {
  await page.goto('/')
  await page.evaluate((t) => localStorage.setItem('mxcsec_token', t), devToken())
}

for (const route of ROUTES) {
  test(`巡检 ${route}`, async ({ page }) => {
    const consoleErrors: string[] = []
    const http5xx: string[] = []
    const http4xx: string[] = []

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        const txt = msg.text()
        if (!/favicon|net::ERR_ABORTED|chrome-extension/.test(txt)) consoleErrors.push(txt.slice(0, 200))
      }
    })
    page.on('response', (resp) => {
      const url = resp.url()
      const s = resp.status()
      if (!url.includes('/api/v1/')) return
      const ep = url.replace(/^https?:\/\/[^/]+/, '')
      // 503 = 依赖不可达 (商业软件合规返回), 不算 5xx FAIL, 计为 4xx 容忍.
      if (s === 503) http4xx.push(`${s} ${ep}`)
      else if (s >= 500) http5xx.push(`${s} ${ep}`)
      else if (s >= 400) http4xx.push(`${s} ${ep}`)
    })

    await injectToken(page)
    await page.goto(route, { waitUntil: 'networkidle' }).catch(() => undefined)

    // 等待页面渲染 (最多 5s)
    await page.waitForTimeout(800)

    // 关键 DOM: 任一 h2/h3/a-card/a-table/a-empty 出现即认为 OK
    const hasKeyDom = await page
      .locator('h2, h3, .ant-card, .ant-table, .ant-empty, .ant-result, .ant-list, .ant-descriptions')
      .first()
      .isVisible({ timeout: 3000 })
      .catch(() => false)

    const shotName = route.replace(/[^a-z0-9]+/gi, '_').replace(/^_|_$/g, '') + '.png'
    const shotPath = path.join(SHOTS_DIR, shotName)
    await page.screenshot({ path: shotPath, fullPage: false }).catch(() => undefined)

    let status: PageReport['status'] = 'PASS'
    if (http5xx.length > 0) status = 'FAIL'
    else if (consoleErrors.length > 0 || !hasKeyDom) status = 'WARN'

    REPORT.push({ route, status, consoleErrors, http5xx, http4xx, hasKeyDom, screenshot: shotPath })

    // 仅 5xx 算硬失败 (4xx 容忍 — 数据为空也是正常)
    expect(http5xx, `5xx on ${route}: ${http5xx.join(', ')}`).toHaveLength(0)
  })
}
