import apiClient from './client'
import type { Vulnerability, VulnerabilityListResult } from './types'
import type { SecurityDBSyncRecord } from './antivirus'

export interface ScanHistoryDetail {
  record: SecurityDBSyncRecord
  vulns: {
    items: Vulnerability[]
    total: number
    page: number
  }
  affectedHosts: {
    hostId: string
    hostname: string
    ip: string
    vulnCount: number
  }[]
}

export interface RemediationCommand {
  packageType: string
  command: string
  description: string
}

export interface RemediationAdvice {
  vulnId: number
  cveId: string
  component: string
  fixedVersion: string
  commands: RemediationCommand[]
  references: string[]
  workaround: string
}

export interface SeverityStats {
  severity: string
  total: number
  patched: number
  unpatched: number
}

export interface HostRemediationStats {
  hostId: string
  hostname: string
  ip: string
  total: number
  patched: number
}

export interface RemediationStats {
  totalVulns: number
  patchedVulns: number
  unpatchedVulns: number
  ignoredVulns: number
  remediationRate: number
  mttr: number
  bySeverity: SeverityStats[]
  topUnpatched: HostRemediationStats[]
}

export interface DailyTrend {
  date: string
  patched: number
  discovered: number
}

export const vulnerabilitiesApi = {
  get: (id: number) => {
    return apiClient.get<Vulnerability>(`/vulnerabilities/${id}`)
  },

  list: (params?: {
    page?: number
    page_size?: number
    host_id?: string
    search?: string
    severity?: string
    status?: string
    component?: string
    exploit_status?: string
    priority?: string
    vuln_category?: string  // P5.1: kernel/shared_lib/web_service/...
    restart_action?: string // P5.5: reboot_host/restart_specific_service/...
    sort?: string
  }) => {
    return apiClient.get<VulnerabilityListResult>('/vulnerabilities', { params })
  },

  ignore: (id: number) => {
    return apiClient.post(`/vulnerabilities/${id}/ignore`)
  },

  triggerSync: () => {
    return apiClient.post('/vulnerabilities/sync')
  },

  triggerScan: (scanType: 'full_scan' | 'incremental_scan' = 'full_scan') => {
    return apiClient.post('/vulnerabilities/scan', { scan_type: scanType })
  },

  getScanStatus: () => {
    return apiClient.get<SecurityDBSyncRecord | { status: string; message: string }>('/vulnerabilities/scan-status')
  },

  getScanHistory: (params?: { page?: number; page_size?: number }) => {
    return apiClient.get<{ total: number; items: SecurityDBSyncRecord[] }>('/vulnerabilities/scan-history', { params })
  },

  getScanHistoryDetail: (id: number, vulnPage = 1, vulnPageSize = 20) => {
    return apiClient.get<ScanHistoryDetail>(
      `/vulnerabilities/scan-history/${id}`,
      { params: { vulnPage, vulnPageSize } },
    )
  },

  // 修复建议
  getAdvice: (id: number) => {
    return apiClient.get<RemediationAdvice>(`/vulnerabilities/${id}/advice`)
  },

  // 标记修复
  patch: (id: number, hostIds?: string[]) => {
    return apiClient.post(`/vulnerabilities/${id}/patch`, hostIds ? { hostIds } : {})
  },

  // 修复统计
  getRemediationStats: () => {
    return apiClient.get<RemediationStats>('/vulnerabilities/stats/remediation')
  },

  // 修复趋势
  getRemediationTrend: (days?: number) => {
    return apiClient.get<DailyTrend[]>('/vulnerabilities/stats/trend', { params: { days } })
  },

  // 取消忽略
  unignore: (id: number) => {
    return apiClient.post(`/vulnerabilities/${id}/unignore`)
  },

  // 优先级分布统计
  getPriorityStats: () => {
    return apiClient.get<{ level: string; count: number }[]>('/vulnerabilities/stats/priority')
  },
}
