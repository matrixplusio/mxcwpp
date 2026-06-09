import apiClient from './client'
import type { Vulnerability, VulnerabilityListResult } from './types'
import type { SecurityDBSyncRecord } from './antivirus'

// 定向扫描请求参数
export interface TriggerScopedScanParams {
  scope: 'global' | 'hosts' | 'business_line'
  host_ids?: string[]
  business_line?: string
  sync_db?: boolean
  reconcile_stale?: boolean
}

// 触发扫描响应
export interface TriggerScanResponse {
  task_id: string
  scope: string
  target_host_count: number
  estimated_seconds: number
}

// 扫描任务
export interface VulnScanTask {
  taskId: string
  scope: string
  businessLine?: string
  status: 'pending' | 'running' | 'success' | 'failed'
  progressTotal: number
  progressScanned: number
  newVulns: number
  patchedCount: number
  vanishedCount: number
  resurfacedCount: number
  errorMsg?: string
  triggeredBy: string
  startedAt?: string
  finishedAt?: string
  createdAt: string
}

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
    // 资产维度分类(P-vuln-classify): os/middleware/app/container/image/unknown
    asset_type?: string
    // 细分(P-vuln-classify Phase4): cloud_agent/monitoring_agent/security_agent/system_tool/system_lib/os_package/business_binary/business_jar
    subscope?: string
    // 修复责任方: ops/sre/dba/dev/image_maintainer/cloud_provider/apm_vendor/platform_team/unknown
    fix_owner?: string
    // CWE 高级分类: rce/privesc/sqli/xss/info_disclosure/dos/path_traversal/ssrf/other
    cwe_category?: string
    // 显示所有(含 advisory orphan 库存),默认仅集群命中
    show_all?: boolean
    sort?: string
  }) => {
    return apiClient.get<VulnerabilityListResult>('/vulnerabilities', { params })
  },

  // 按 fix_owner / asset_type 导出 CSV(P-vuln-classify Phase 3)
  exportByOwner: (params: {
    fix_owner?: string
    asset_type?: string
    business_line?: string
    severity?: string  // 逗号分隔: critical,high
  }) => {
    return apiClient.get('/vulnerabilities/export-by-owner', {
      params,
      responseType: 'blob',
    })
  },

  // 按 asset_type × severity 统计(用于主机详情漏洞 tab 徽章)
  statsAssetType: (params?: { host_id?: string; business_line?: string }) => {
    return apiClient.get<{
      asset_types: Array<{ key: string; critical: number; high: number; medium: number; low: number; total: number }>
      fix_owners: Array<{ key: string; critical: number; high: number; medium: number; low: number; total: number }>
    }>('/vulnerabilities/stats/asset-type', { params })
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

  // 定向扫描（targeted scan v1）：按 scope/hosts/business_line 触发
  triggerScopedScan: (params: TriggerScopedScanParams) => {
    return apiClient.post<TriggerScanResponse>('/vulnerabilities/scan', params)
  },

  getScanTask: (taskID: string) => {
    return apiClient.get<VulnScanTask>(`/vulnerabilities/scan-tasks/${taskID}`)
  },

  listScanTasks: (status?: string, limit = 20) => {
    return apiClient.get<{ items: VulnScanTask[]; count: number }>(
      '/vulnerabilities/scan-tasks',
      { params: { status, limit } },
    )
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
