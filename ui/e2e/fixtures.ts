/**
 * Shared fixtures: authenticated page (logs in once per worker, reuses token).
 *
 * 直接用 JWT_SECRET HMAC-SHA256 签 token, 绕过 captcha. dev/CI 通用.
 */
import { test as base, expect, Page } from '@playwright/test'
import { createHmac } from 'node:crypto'

const USER = process.env.E2E_USERNAME || 'admin'
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production!!'

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function signDevToken(username = USER, role = 'admin', tenant = 'default'): string {
  const hdr = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const now = Math.floor(Date.now() / 1000)
  const payload = b64url(
    JSON.stringify({
      username,
      role,
      tenant_id: tenant,
      is_platform_admin: role === 'admin' && tenant === 'default',
      iss: 'mxsec-platform',
      iat: now,
      exp: now + 3600,
    }),
  )
  const sig = b64url(createHmac('sha256', SECRET).update(`${hdr}.${payload}`).digest())
  return `${hdr}.${payload}.${sig}`
}

async function loginViaAPI(page: Page) {
  const token = signDevToken()
  await page.goto('/')
  await page.evaluate((t) => {
    localStorage.setItem('mxcsec_token', t)
  }, token)
}

export const test = base.extend<{ authedPage: Page }>({
  authedPage: async ({ page }, use) => {
    await loginViaAPI(page)
    await use(page)
  },
})

export { expect }
