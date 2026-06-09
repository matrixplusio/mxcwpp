/**
 * P2-10: 通用 Blob 下载 helper.
 *
 * 审计找的 9 个 createObjectURL 站点全部已配对 revokeObjectURL ✅, 实际无内存泄漏.
 * 但散落 9 处 boilerplate 易未来漏写. 此 helper 集中:
 *
 *   1. createObjectURL → 临时 <a> click → revoke (try/finally 保证)
 *   2. 自动 cleanup DOM 节点
 *   3. 类型化 API 防误用
 *
 * 用法:
 *
 *   import { downloadBlob } from '@/utils/download'
 *   const blob = await api.exportPDF(...)
 *   downloadBlob(blob, 'report.pdf')
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.style.display = 'none'
    document.body.appendChild(a)
    try {
      a.click()
    } finally {
      document.body.removeChild(a)
    }
  } finally {
    // 异步 revoke 给浏览器时间开始下载 (Chrome 安全要求, 立即 revoke 偶发下载取消)
    setTimeout(() => URL.revokeObjectURL(url), 100)
  }
}

/**
 * downloadJSON 序列化 JSON + 下载, 集中 9 处 vue 文件中的 boilerplate.
 */
export function downloadJSON(data: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: 'application/json',
  })
  downloadBlob(blob, filename)
}

/**
 * downloadCSV 给原始 csv 字符串包 Blob + 下载, 加 BOM 防 Excel 中文乱码.
 */
export function downloadCSV(csvContent: string, filename: string): void {
  const bom = '﻿'
  const blob = new Blob([bom + csvContent], { type: 'text/csv;charset=utf-8' })
  downloadBlob(blob, filename)
}

/**
 * downloadText 任意文本下载.
 */
export function downloadText(text: string, filename: string, mime = 'text/plain'): void {
  const blob = new Blob([text], { type: mime + ';charset=utf-8' })
  downloadBlob(blob, filename)
}
