import apiClient from './client'
import type { PaginatedResponse } from './types'

export type AlertSource = 'baseline' | 'detection' | 'agent' | 'vulnerability' | 'fim' | 'virus' | 'kube'

export interface Alert {
  id: number
  result_id: string
  host_id: string
  rule_id: string
  policy_id: string
  source: AlertSource
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  title: string
  description?: string
  actual?: string
  expected?: string
  fix_suggestion?: string
  status: 'active' | 'resolved' | 'ignored'
  first_seen_at: string
  last_seen_at: string
  resolved_at?: string
  resolved_by?: string
  resolve_reason?: string
  created_at: string
  updated_at: string
  host?: {
    host_id: string
    hostname: string
    ipv4: string[]
  }
  rule?: {
    rule_id: string
    title: string
  }
}

export interface AlertStatistics {
  total: number
  active: number
  resolved: number
  ignored: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface ListAlertsParams {
  page?: number
  page_size?: number
  status?: 'active' | 'resolved' | 'ignored'
  severity?: 'critical' | 'high' | 'medium' | 'low'
  host_id?: string
  rule_id?: string
  category?: string
  alert_type?: AlertSource
  keyword?: string
  result_id?: string
  runtime_type?: string
  business_line?: string
  mitre_id?: string
  start_time?: string
  end_time?: string
}

export interface AlertWhitelist {
  id: number
  name: string
  rule_id: string
  host_id: string
  category: string
  severity: string
  source_ip_cidr: string
  reason: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface CreateWhitelistParams {
  name: string
  rule_id?: string
  host_id?: string
  category?: string
  severity?: string
  source_ip_cidr?: string
  reason?: string
}

export const alertsApi = {
  // 获取告警列表
  list: (params?: ListAlertsParams) => {
    return apiClient.get<PaginatedResponse<Alert>>('/alerts', { params })
  },

  // 获取告警详情
  get: (id: number) => {
    return apiClient.get<Alert>(`/alerts/${id}`)
  },

  // 获取告警统计
  statistics: () => {
    return apiClient.get<AlertStatistics>('/alerts/statistics')
  },

  // 解决告警
  resolve: (id: number, reason?: string) => {
    return apiClient.post(`/alerts/${id}/resolve`, { reason })
  },

  // 忽略告警
  ignore: (id: number) => {
    return apiClient.post(`/alerts/${id}/ignore`)
  },

  // 批量解决告警
  batchResolve: (ids: number[], reason?: string) => {
    return apiClient.post('/alerts/batch/resolve', { ids, reason })
  },

  // 批量忽略告警
  batchIgnore: (ids: number[]) => {
    return apiClient.post('/alerts/batch/ignore', { ids })
  },

  // 批量删除告警
  batchDelete: (ids: number[]) => {
    return apiClient.post('/alerts/batch/delete', { ids })
  },
}

export const alertWhitelistApi = {
  list: (params?: { page?: number; page_size?: number; keyword?: string }) => {
    return apiClient.get<{ items: AlertWhitelist[]; total: number }>('/alerts/whitelist', { params })
  },

  create: (data: CreateWhitelistParams) => {
    return apiClient.post<AlertWhitelist>('/alerts/whitelist', data)
  },

  update: (id: number, data: CreateWhitelistParams) => {
    return apiClient.put<AlertWhitelist>(`/alerts/whitelist/${id}`, data)
  },

  delete: (id: number) => {
    return apiClient.delete(`/alerts/whitelist/${id}`)
  },
}
