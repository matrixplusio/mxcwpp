import apiClient from './client'

export interface VulnBulletin {
  id: number
  bulletinNo: string
  vulnId: number
  cveId: string
  priority: string // P0/P1/P2/P3
  priorityFactors: PriorityFactors
  component: string
  severity: string
  cvssScore: number
  cvssVector: string
  vulnType: string
  attackVector: string
  description: string
  affectedAssets: number
  affectedVersions: string
  fixedVersion: string
  fixSuggestion: string
  workaround: string
  patchAvailable: boolean
  source: string
  hasExploit: boolean
  inKev: boolean
  epssScore: number
  exploitRef: string
  status: string
  notifiedAt?: string
  acknowledgedAt?: string
  acknowledgedBy?: string
  resolvedAt?: string
  resolvedBy?: string
  resolveComment?: string
  ignoredAt?: string
  ignoredBy?: string
  ignoreReason?: string
  slaAckDeadline?: string
  slaResolveDeadline?: string
  slaBreached: boolean
  notifyCount: number
  lastNotifiedAt?: string
  createdAt: string
  updatedAt: string
}

export interface PriorityFactors {
  cvss_score: number
  cvss_vector?: string
  attack_vector: string
  vuln_type: string
  has_exploit: boolean
  in_kev: boolean
  patch_available: boolean
  epss_score?: number
  reason: string
}

export interface BulletinStatistics {
  active: number
  sla_breached: number
  by_priority: Record<string, number>
  by_status: Record<string, number>
}

export interface VulnBulletinConfig {
  enabled: boolean
  auto_create: boolean
  notify_priorities: string[]
  p0_ack_hours: number
  p0_resolve_hours: number
  p1_ack_hours: number
  p1_resolve_hours: number
  p2_ack_hours: number
  p2_resolve_hours: number
  p3_ack_hours: number
  p3_resolve_hours: number
  escalation_enabled: boolean
  p0_escalation_minutes: number
  p1_escalation_minutes: number
}

export const vulnBulletinsApi = {
  list: (params?: {
    page?: number
    page_size?: number
    priority?: string
    status?: string
    cve_id?: string
    component?: string
    search?: string
    sla_breached?: string
    sort?: string
  }) => apiClient.get<{ total: number; items: VulnBulletin[] }>('/vuln-bulletins', { params }),

  get: (id: number) => apiClient.get<{ bulletin: VulnBulletin; affected_hosts: any[] }>(`/vuln-bulletins/${id}`),

  statistics: () => apiClient.get<BulletinStatistics>('/vuln-bulletins/statistics'),

  acknowledge: (id: number) => apiClient.put(`/vuln-bulletins/${id}/acknowledge`),

  resolve: (id: number, comment?: string) =>
    apiClient.put(`/vuln-bulletins/${id}/resolve`, { comment }),

  ignore: (id: number, reason?: string) =>
    apiClient.put(`/vuln-bulletins/${id}/ignore`, { reason }),

  reopen: (id: number) => apiClient.put(`/vuln-bulletins/${id}/reopen`),

  batch: (ids: number[], action: string, reason?: string) =>
    apiClient.post('/vuln-bulletins/batch', { ids, action, reason }),

  getConfig: () => apiClient.get<VulnBulletinConfig>('/vuln-bulletins/config'),

  updateConfig: (config: VulnBulletinConfig) =>
    apiClient.put('/vuln-bulletins/config', config),
}
