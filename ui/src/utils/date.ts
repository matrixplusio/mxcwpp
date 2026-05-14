/**
 * 日期时间格式化工具函数
 */

/**
 * 解析日期字符串，支持多种格式，并转换为东八区时间
 * @param dateStr 日期字符串，支持 ISO 8601 格式或 YYYY-MM-DD HH:mm:ss 格式
 * @returns Date 对象，如果解析失败返回 null
 */
const parseDate = (dateStr: string | null | undefined): Date | null => {
  if (!dateStr) return null

  try {
    // 尝试直接解析（支持 ISO 8601 和 YYYY-MM-DD HH:mm:ss 格式）
    let date = new Date(dateStr)

    // 如果直接解析失败，尝试将空格替换为 T（兼容 YYYY-MM-DD HH:mm:ss 格式）
    if (isNaN(date.getTime()) && typeof dateStr === 'string' && dateStr.includes(' ')) {
      date = new Date(dateStr.replace(' ', 'T'))
    }

    if (isNaN(date.getTime())) return null

    // 如果日期字符串包含 'Z' 或 '+00:00'，说明是 UTC 时间，需要转换为东八区
    // 注意：JavaScript 的 Date 对象会自动根据浏览器时区显示，但我们需要确保显示东八区时间
    // 如果字符串是 UTC 格式（如 2026-01-26T12:00:00Z），Date 对象已经是正确的时间戳
    // getHours() 等方法会根据浏览器时区返回，所以我们需要手动调整到东八区

    return date
  } catch (error) {
    return null
  }
}

/**
 * 将 Date 对象转换为东八区时间的各个部分
 * @param date Date 对象
 * @returns 东八区时间的年月日时分秒
 */
const toBeijingTime = (date: Date) => {
  // 获取 UTC 时间戳
  const utcTime = date.getTime()

  // 东八区偏移量：8小时 = 8 * 60 * 60 * 1000 毫秒
  const beijingOffset = 8 * 60 * 60 * 1000

  // 获取浏览器时区偏移量（分钟）
  const localOffset = date.getTimezoneOffset() * 60 * 1000

  // 计算东八区时间：UTC时间 + 东八区偏移 - 本地偏移
  const beijingTime = new Date(utcTime + beijingOffset + localOffset)

  return {
    year: beijingTime.getFullYear(),
    month: beijingTime.getMonth() + 1,
    day: beijingTime.getDate(),
    hours: beijingTime.getHours(),
    minutes: beijingTime.getMinutes(),
    seconds: beijingTime.getSeconds(),
  }
}

/**
 * 格式化日期时间，显示为完整格式（东八区时间）
 * @param dateStr 日期字符串，支持 ISO 8601 或 YYYY-MM-DD HH:mm:ss 格式
 * @returns 格式化后的日期字符串，格式：YYYY-MM-DD HH:mm
 */
export const formatDateTime = (dateStr: string | null | undefined): string => {
  const date = parseDate(dateStr)
  if (!date) return '-'

  try {
    const { year, month, day, hours, minutes } = toBeijingTime(date)

    // 始终显示完整日期时间格式：YYYY-MM-DD HH:mm
    return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')} ${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`
  } catch (error) {
    console.error('日期格式化失败:', error)
    return '-'
  }
}

/**
 * 格式化完整日期时间，始终显示年份（东八区时间）
 * @param dateStr 日期字符串，支持 ISO 8601 或 YYYY-MM-DD HH:mm:ss 格式
 * @returns 格式化后的日期字符串，格式：YYYY-MM-DD HH:mm
 */
export const formatFullDateTime = (dateStr: string | null | undefined): string => {
  const date = parseDate(dateStr)
  if (!date) return '-'

  try {
    const { year, month, day, hours, minutes } = toBeijingTime(date)

    return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')} ${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`
  } catch (error) {
    console.error('日期格式化失败:', error)
    return '-'
  }
}

/**
 * 格式化日期，只显示日期部分（东八区时间）
 * @param dateStr 日期字符串，支持 ISO 8601 或 YYYY-MM-DD HH:mm:ss 格式
 * @returns 格式化后的日期字符串，格式：YYYY-MM-DD
 */
export const formatDate = (dateStr: string | null | undefined): string => {
  const date = parseDate(dateStr)
  if (!date) return '-'

  try {
    const { year, month, day } = toBeijingTime(date)

    return `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`
  } catch (error) {
    console.error('日期格式化失败:', error)
    return '-'
  }
}

/**
 * 格式化相对时间（如：2小时前、3天前）
 * @param dateStr 日期字符串，支持 ISO 8601 或 YYYY-MM-DD HH:mm:ss 格式
 * @returns 相对时间字符串
 */
export const formatRelativeTime = (dateStr: string | null | undefined): string => {
  const date = parseDate(dateStr)
  if (!date) return '-'

  try {
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffSeconds = Math.floor(diffMs / 1000)
    const diffMinutes = Math.floor(diffSeconds / 60)
    const diffHours = Math.floor(diffMinutes / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffSeconds < 60) {
      return '刚刚'
    } else if (diffMinutes < 60) {
      return `${diffMinutes}分钟前`
    } else if (diffHours < 24) {
      return `${diffHours}小时前`
    } else if (diffDays < 7) {
      return `${diffDays}天前`
    } else {
      // 超过7天，显示具体日期
      return formatDateTime(dateStr)
    }
  } catch (error) {
    console.error('相对时间格式化失败:', error)
    return '-'
  }
}
