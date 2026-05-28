/**
 * 严重度 & 状态 — 单一色值来源
 * 所有视图统一从此处引用，禁止硬编码色值
 */

// ── 严重度 ──────────────────────────────────────────────

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SeverityConfig {
  label: string
  color: string
  bgColor: string
  borderColor: string
  tagColor: string // ant-design-vue <a-tag> 预设色名（有预设用预设，没有用 hex）
}

export const SEVERITY_MAP: Record<SeverityLevel, SeverityConfig> = {
  critical: {
    label: '严重',
    color: '#EF4444',
    bgColor: 'rgba(239, 68, 68, 0.12)',
    borderColor: 'rgba(239, 68, 68, 0.3)',
    tagColor: 'red',
  },
  high: {
    label: '高危',
    color: '#F59E0B',
    bgColor: 'rgba(245, 158, 11, 0.12)',
    borderColor: 'rgba(245, 158, 11, 0.3)',
    tagColor: 'orange',
  },
  medium: {
    label: '中危',
    color: '#FADC19',
    bgColor: 'rgba(250, 220, 25, 0.12)',
    borderColor: 'rgba(250, 220, 25, 0.3)',
    tagColor: 'gold',
  },
  low: {
    label: '低危',
    color: '#3B82F6',
    bgColor: 'rgba(59, 130, 246, 0.12)',
    borderColor: 'rgba(59, 130, 246, 0.3)',
    tagColor: 'blue',
  },
  info: {
    label: '信息',
    color: '#6B7280',
    bgColor: 'rgba(107, 114, 128, 0.12)',
    borderColor: 'rgba(107, 114, 128, 0.3)',
    tagColor: 'default',
  },
}

export const getSeverityConfig = (level: string): SeverityConfig => {
  return SEVERITY_MAP[level as SeverityLevel] ?? SEVERITY_MAP.info
}

export const getSeverityColor = (level: string): string => {
  return getSeverityConfig(level).color
}

export const getSeverityLabel = (level: string): string => {
  return getSeverityConfig(level).label
}

// ── 主机状态 ──────────────────────────────────────────────

export type HostStatus = 'online' | 'offline'

export const HOST_STATUS_MAP: Record<HostStatus, { label: string; color: string; tagColor: string }> = {
  online: { label: '在线', color: '#22C55E', tagColor: 'green' },
  offline: { label: '离线', color: '#EF4444', tagColor: 'red' },
}

export const getHostStatusConfig = (status: string) => {
  return HOST_STATUS_MAP[status as HostStatus] ?? { label: status, color: '#6B7280', tagColor: 'default' }
}

// ── 合规状态 ──────────────────────────────────────────────

export type ComplianceStatus = 'pass' | 'fail' | 'warn' | 'error' | 'skip'

export const COMPLIANCE_STATUS_MAP: Record<ComplianceStatus, { label: string; color: string; tagColor: string }> = {
  pass: { label: '通过', color: '#22C55E', tagColor: 'green' },
  fail: { label: '不通过', color: '#EF4444', tagColor: 'red' },
  warn: { label: '警告', color: '#F59E0B', tagColor: 'orange' },
  error: { label: '错误', color: '#EF4444', tagColor: 'red' },
  skip: { label: '跳过', color: '#6B7280', tagColor: 'default' },
}

// ── 通用任务状态 ──────────────────────────────────────────

export type TaskStatus = 'pending' | 'running' | 'success' | 'failed' | 'cancelled' | 'timeout'

export const TASK_STATUS_MAP: Record<TaskStatus, { label: string; color: string; tagColor: string }> = {
  pending: { label: '等待中', color: '#6B7280', tagColor: 'default' },
  running: { label: '执行中', color: '#3B82F6', tagColor: 'blue' },
  success: { label: '成功', color: '#22C55E', tagColor: 'green' },
  failed: { label: '失败', color: '#EF4444', tagColor: 'red' },
  cancelled: { label: '已取消', color: '#6B7280', tagColor: 'default' },
  timeout: { label: '超时', color: '#F59E0B', tagColor: 'orange' },
}

// ── 漏洞状态 ──────────────────────────────────────────────

export type VulnStatus = 'unpatched' | 'patched' | 'ignored' | 'fixing'

export const VULN_STATUS_MAP: Record<VulnStatus, { label: string; color: string; tagColor: string }> = {
  unpatched: { label: '未修复', color: '#EF4444', tagColor: 'red' },
  patched: { label: '已修复', color: '#22C55E', tagColor: 'green' },
  ignored: { label: '已忽略', color: '#6B7280', tagColor: 'default' },
  fixing: { label: '修复中', color: '#3B82F6', tagColor: 'blue' },
}
