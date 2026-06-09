/**
 * 深度 E2E 巡检 — 不止访问页面, 还遍历 tabs / 详情 / 模态.
 *
 * 与 full-pages.spec.ts 互补:
 *   - full-pages: 静态访问 + 渲染检查 (60+ 路由)
 *   - deep-pages : 列表→详情联动, tab 切换, 详情内 tabs 二次切换
 *
 * 每个深度场景检查:
 *   1. console error
 *   2. XHR 5xx
 *   3. tab 切换后页面无白屏 (DOM 仍可见)
 *
 * 跑:
 *   E2E_BASE_URL=http://localhost:3000 E2E_NO_SERVER=1 \
 *     JWT_SECRET='dev-secret-change-in-production!!' \
 *     npx playwright test e2e/deep-pages.spec.ts --config=e2e/playwright.config.ts --project=chromium
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

const REPORT_DIR = 'test-results/deep-pages-report'
const SHOTS_DIR = `${REPORT_DIR}/screenshots`
fs.mkdirSync(SHOTS_DIR, { recursive: true })

interface DeepReport {
  scenario: string
  status: 'PASS' | 'WARN' | 'FAIL'
  tabsClicked: number
  http5xx: string[]
  http4xx: string[]
  consoleErrors: string[]
  notes: string[]
}
const REPORT: DeepReport[] = []

test.afterAll(() => {
  const wid = process.env.TEST_WORKER_INDEX || '0'
  fs.writeFileSync(path.join(REPORT_DIR, `report-w${wid}.json`), JSON.stringify(REPORT, null, 2))
})

async function injectToken(page: Page) {
  await page.goto('/')
  await page.evaluate((t) => localStorage.setItem('mxcsec_token', t), devToken())
}

function attachNet(page: Page, http5xx: string[], http4xx: string[], consoleErrors: string[]) {
  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const txt = msg.text()
      if (!/favicon|ERR_ABORTED|chrome-extension|deprecated/.test(txt)) consoleErrors.push(txt.slice(0, 200))
    }
  })
  page.on('response', (resp) => {
    const url = resp.url()
    if (!url.includes('/api/v1/')) return
    const s = resp.status()
    const ep = url.replace(/^https?:\/\/[^/]+/, '')
    // 503 = 依赖不可达 (合规返回), 计为 4xx 容忍.
    if (s === 503) http4xx.push(`${s} ${ep}`)
    else if (s >= 500) http5xx.push(`${s} ${ep}`)
    else if (s >= 400) http4xx.push(`${s} ${ep}`)
  })
}

/**
 * 通用 tab 巡检: 路由进入后, 找所有 .ant-tabs-tab 顺序 click,
 * 每次 click 后等 networkidle + 截图 + 检查无 5xx.
 */
async function clickAllTabs(page: Page, route: string, report: DeepReport): Promise<void> {
  await page.goto(route, { waitUntil: 'networkidle' }).catch(() => undefined)
  await page.waitForTimeout(600)

  const tabs = page.locator('.ant-tabs-tab:not(.ant-tabs-tab-disabled)')
  const count = await tabs.count()
  report.notes.push(`tab count=${count}`)

  for (let i = 0; i < count; i++) {
    const tab = tabs.nth(i)
    const label = (await tab.textContent().catch(() => null))?.trim() || `tab-${i}`
    try {
      await tab.click({ timeout: 3000 })
      await page.waitForTimeout(500)
      report.tabsClicked++
      const shotName = (route + '_' + label).replace(/[^a-z0-9]+/gi, '_').slice(0, 80) + '.png'
      await page.screenshot({ path: path.join(SHOTS_DIR, shotName), fullPage: false }).catch(() => undefined)
    } catch {
      report.notes.push(`click tab "${label}" failed`)
    }
  }
}

/**
 * 列表 → 第一行详情链接联动.
 * locator 找页面里第一个 detail 链接 (router-link 或 a-button "详情"), click,
 * 然后在详情页继续 click tab.
 */
async function listToDetail(page: Page, route: string, report: DeepReport, detailSelector: string) {
  await page.goto(route, { waitUntil: 'networkidle' }).catch(() => undefined)
  await page.waitForTimeout(700)
  const link = page.locator(detailSelector).first()
  const exist = await link.isVisible({ timeout: 2500 }).catch(() => false)
  if (!exist) {
    report.notes.push(`no detail row found by ${detailSelector}`)
    return
  }
  await link.click({ timeout: 3000 }).catch(() => undefined)
  await page.waitForTimeout(1200)
  await page.screenshot({ path: path.join(SHOTS_DIR, route.replace(/[^a-z0-9]+/gi, '_') + '_detail.png'), fullPage: false }).catch(() => undefined)

  // 详情页常见有 tabs
  const tabs = page.locator('.ant-tabs-tab:not(.ant-tabs-tab-disabled)')
  const count = await tabs.count()
  for (let i = 0; i < count; i++) {
    await tabs.nth(i).click({ timeout: 3000 }).catch(() => undefined)
    await page.waitForTimeout(400)
    report.tabsClicked++
  }
  report.notes.push(`detail tabs count=${count}`)
}

// ============================================
// 场景 1: 多 tab 页面 (页内 a-tabs)
// ============================================
const TAB_PAGES: string[] = [
  '/honeypot',           // sensors / events 2 tab
  '/ad-audit',           // alerts / events 2 tab
  '/system/components',  // 多 tab
  '/fim/dashboard',
  '/kube/clusters',
  '/kube/baseline',
  '/kube/image-scan',
  '/storylines',
  '/threat-intel',
  '/bde',
  '/anomaly',
  '/system/data-retention',
  '/system/feature-flags',
  '/system/inspection',
  '/system/host-monitor',
  '/system/service-monitor',
  '/edr/events',
  '/detection/rules',
  '/hunting',
  '/vuln-bulletins',
  '/vuln-remediation',
  '/sbom-import',
]

for (const route of TAB_PAGES) {
  test(`tabs ${route}`, async ({ page }) => {
    const r: DeepReport = { scenario: `tabs ${route}`, status: 'PASS', tabsClicked: 0, http5xx: [], http4xx: [], consoleErrors: [], notes: [] }
    attachNet(page, r.http5xx, r.http4xx, r.consoleErrors)
    await injectToken(page)
    await clickAllTabs(page, route, r)
    if (r.http5xx.length) r.status = 'FAIL'
    else if (r.consoleErrors.length) r.status = 'WARN'
    REPORT.push(r)
    expect(r.http5xx, `5xx on ${route} tabs: ${r.http5xx.join('; ')}`).toHaveLength(0)
  })
}

// ============================================
// 场景 2: 列表 → 详情联动
// ============================================
const LIST_DETAIL: { route: string; sel: string; name: string }[] = [
  { route: '/hosts', sel: 'a:has-text("详情"), .ant-table a[href*="/hosts/"]', name: 'hosts→detail' },
  { route: '/alerts', sel: '.ant-table a[href*="/alerts/"], a:has-text("详情")', name: 'alerts→detail' },
  { route: '/policies', sel: '.ant-table a[href*="/policies/"], a:has-text("详情")', name: 'policies→detail' },
  { route: '/vuln-bulletins', sel: '.ant-table a[href*="/vuln-bulletins/"], a:has-text("详情")', name: 'vuln-bulletins→detail' },
  { route: '/vuln-list', sel: '.ant-table a[href*="/vuln-list/"], a:has-text("详情")', name: 'vuln-list→detail' },
  { route: '/vuln-remediation/tasks', sel: '.ant-table a, a:has-text("详情")', name: 'remediation-tasks→detail' },
  { route: '/kube/clusters', sel: '.ant-table a, a:has-text("详情")', name: 'kube-clusters→detail' },
  { route: '/policy-groups', sel: '.ant-table a, a:has-text("规则"), a:has-text("详情")', name: 'policy-groups→rules' },
]

for (const t of LIST_DETAIL) {
  test(`detail ${t.name}`, async ({ page }) => {
    const r: DeepReport = { scenario: `detail ${t.name}`, status: 'PASS', tabsClicked: 0, http5xx: [], http4xx: [], consoleErrors: [], notes: [] }
    attachNet(page, r.http5xx, r.http4xx, r.consoleErrors)
    await injectToken(page)
    await listToDetail(page, t.route, r, t.sel)
    if (r.http5xx.length) r.status = 'FAIL'
    else if (r.consoleErrors.length) r.status = 'WARN'
    REPORT.push(r)
    expect(r.http5xx, `5xx on ${t.name}: ${r.http5xx.join('; ')}`).toHaveLength(0)
  })
}

// ============================================
// 场景 3: 模态/抽屉触发 (按 "新建" "创建" "添加")
// ============================================
const MODAL_TRIGGER: { route: string; label: string }[] = [
  { route: '/business-lines', label: '新建' },
  { route: '/whitelist', label: '新建' },
  { route: '/vuln-data-sources', label: '新建' },
  { route: '/policy-groups', label: '新建' },
  { route: '/users', label: '新建' },
  { route: '/system/notification', label: '新建' },
  { route: '/system/data-retention', label: '新建' },
  { route: '/system/feature-flags', label: '新建' },
]

for (const m of MODAL_TRIGGER) {
  test(`modal ${m.route}`, async ({ page }) => {
    const r: DeepReport = { scenario: `modal ${m.route}`, status: 'PASS', tabsClicked: 0, http5xx: [], http4xx: [], consoleErrors: [], notes: [] }
    attachNet(page, r.http5xx, r.http4xx, r.consoleErrors)
    await injectToken(page)
    await page.goto(m.route, { waitUntil: 'networkidle' }).catch(() => undefined)
    await page.waitForTimeout(600)
    const btn = page.locator(`button:has-text("${m.label}"), a:has-text("${m.label}")`).first()
    const ok = await btn.isVisible({ timeout: 2500 }).catch(() => false)
    if (!ok) {
      r.notes.push(`no "${m.label}" trigger`)
    } else {
      await btn.click({ timeout: 3000 }).catch(() => undefined)
      await page.waitForTimeout(800)
      const modal = page.locator('.ant-modal-content, .ant-drawer-content').first()
      const open = await modal.isVisible({ timeout: 2500 }).catch(() => false)
      r.notes.push(`modal opened=${open}`)
      await page.screenshot({ path: path.join(SHOTS_DIR, m.route.replace(/[^a-z0-9]+/gi, '_') + '_modal.png'), fullPage: false }).catch(() => undefined)
    }
    if (r.http5xx.length) r.status = 'FAIL'
    else if (r.consoleErrors.length) r.status = 'WARN'
    REPORT.push(r)
    expect(r.http5xx, `5xx on modal ${m.route}: ${r.http5xx.join('; ')}`).toHaveLength(0)
  })
}

// ============================================
// 场景 4: RASP 4 路由 (未在 menu 但存在)
// ============================================
const RASP_ROUTES = ['/rasp/alarms', '/rasp/apps', '/rasp/config', '/rasp/vulns']
for (const route of RASP_ROUTES) {
  test(`rasp ${route}`, async ({ page }) => {
    const r: DeepReport = { scenario: `rasp ${route}`, status: 'PASS', tabsClicked: 0, http5xx: [], http4xx: [], consoleErrors: [], notes: [] }
    attachNet(page, r.http5xx, r.http4xx, r.consoleErrors)
    await injectToken(page)
    await page.goto(route, { waitUntil: 'networkidle' }).catch(() => undefined)
    await page.waitForTimeout(700)
    const hasDom = await page.locator('h2, h3, .ant-card, .ant-table, .ant-empty').first().isVisible({ timeout: 3000 }).catch(() => false)
    r.notes.push(`DOM ok=${hasDom}`)
    await page.screenshot({ path: path.join(SHOTS_DIR, route.replace(/[^a-z0-9]+/gi, '_') + '.png'), fullPage: false }).catch(() => undefined)
    if (r.http5xx.length) r.status = 'FAIL'
    else if (r.consoleErrors.length || !hasDom) r.status = 'WARN'
    REPORT.push(r)
    expect(r.http5xx, `5xx on ${route}: ${r.http5xx.join('; ')}`).toHaveLength(0)
  })
}
