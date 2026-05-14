import { describe, it, expect } from 'vitest'
import { formatDateTime, formatFullDateTime, formatDate, formatRelativeTime } from '../date'

describe('formatDateTime', () => {
  it('返回 "-" 当输入为 null', () => {
    expect(formatDateTime(null)).toBe('-')
  })

  it('返回 "-" 当输入为 undefined', () => {
    expect(formatDateTime(undefined)).toBe('-')
  })

  it('返回 "-" 当输入为空字符串', () => {
    expect(formatDateTime('')).toBe('-')
  })

  it('格式化 YYYY-MM-DD HH:mm:ss 格式的日期', () => {
    const result = formatDateTime('2026-05-07 12:30:00')
    // 结果应该是 YYYY-MM-DD HH:mm 格式
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  })

  it('格式化 ISO 8601 格式的日期', () => {
    const result = formatDateTime('2026-05-07T12:30:00Z')
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  })

  it('返回 "-" 当输入为无效日期字符串', () => {
    expect(formatDateTime('not-a-date')).toBe('-')
  })
})

describe('formatFullDateTime', () => {
  it('返回 "-" 当输入为 null', () => {
    expect(formatFullDateTime(null)).toBe('-')
  })

  it('格式化日期为完整格式', () => {
    const result = formatFullDateTime('2026-01-15 08:00:00')
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  })
})

describe('formatDate', () => {
  it('返回 "-" 当输入为 null', () => {
    expect(formatDate(null)).toBe('-')
  })

  it('返回 "-" 当输入为 undefined', () => {
    expect(formatDate(undefined)).toBe('-')
  })

  it('只返回日期部分', () => {
    const result = formatDate('2026-05-07 12:30:00')
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })

  it('格式化 ISO 格式只返回日期', () => {
    const result = formatDate('2026-12-25T00:00:00Z')
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/)
  })
})

describe('formatRelativeTime', () => {
  it('返回 "-" 当输入为 null', () => {
    expect(formatRelativeTime(null)).toBe('-')
  })

  it('返回 "刚刚" 当时间在 60 秒以内', () => {
    const now = new Date()
    const result = formatRelativeTime(now.toISOString())
    expect(result).toBe('刚刚')
  })

  it('返回 "X分钟前" 当时间在 1 小时以内', () => {
    const date = new Date(Date.now() - 30 * 60 * 1000) // 30 分钟前
    const result = formatRelativeTime(date.toISOString())
    expect(result).toBe('30分钟前')
  })

  it('返回 "X小时前" 当时间在 24 小时以内', () => {
    const date = new Date(Date.now() - 5 * 60 * 60 * 1000) // 5 小时前
    const result = formatRelativeTime(date.toISOString())
    expect(result).toBe('5小时前')
  })

  it('返回 "X天前" 当时间在 7 天以内', () => {
    const date = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000) // 3 天前
    const result = formatRelativeTime(date.toISOString())
    expect(result).toBe('3天前')
  })

  it('超过 7 天返回具体日期', () => {
    const date = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 天前
    const result = formatRelativeTime(date.toISOString())
    // 超过 7 天应该返回格式化后的日期
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  })
})
