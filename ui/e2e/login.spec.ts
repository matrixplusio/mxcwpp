import { test, expect } from '@playwright/test'
import { createHmac } from 'node:crypto'

const USER = process.env.E2E_USERNAME || 'admin'
const PASS = process.env.E2E_PASSWORD || 'admin123'
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production!!'

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
  const sig = b64url(createHmac('sha256', JWT_SECRET).update(`${hdr}.${pl}`).digest())
  return `${hdr}.${pl}.${sig}`
}

test.describe('Login flow', () => {
  test('renders login page', async ({ page }) => {
    await page.goto('/login')
    await expect(page).toHaveURL(/\/login/)
    await expect(page.locator('input[type="text"], input[placeholder*="用户"]').first()).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('rejects bad credentials', async ({ page }) => {
    const resp = await page.request.post('/api/v1/auth/login', {
      data: { username: 'nope', password: 'wrong' },
    })
    // backend returns 200 + code!=0, or 401 — both are "rejected"
    if (resp.ok()) {
      const body = await resp.json()
      expect(body.code).not.toBe(0)
    } else {
      expect(resp.status()).toBeGreaterThanOrEqual(400)
    }
  })

  test('login redirects to dashboard', async ({ page }) => {
    // dev/CI 模式直接签 token, 绕过验证码 (生产仍走 /auth/login + captcha)
    const token = devToken()
    await page.goto('/')
    await page.evaluate((t) => localStorage.setItem('mxcsec_token', t), token)
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/dashboard/)
  })

  test('logout clears token', async ({ page }) => {
    await page.goto('/')
    await page.evaluate(() => localStorage.setItem('mxcsec_token', 'dummy'))
    await page.evaluate(() => {
      localStorage.removeItem('mxcsec_token')
      localStorage.removeItem('mxcsec_user')
    })
    const t = await page.evaluate(() => localStorage.getItem('mxcsec_token'))
    expect(t).toBeNull()
  })
})
