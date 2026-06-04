import apiClient from './client'
import type { PaginatedResponse } from './types'

// 单个触发指标
export interface ElevatedMetric {
  name: string
  current: number
  baseline: number
  ratio: number
}

// 异常告警触发证据 + 攻击链 IOC
export interface AnomalyTriggerContext {
  elevated_metrics?: ElevatedMetric[]
  metric_snapshot?: Record<string, number>
  suspicious_ips?: string[]
  suspicious_domains?: string[]
  sensitive_files?: string[]
  process_chain?: string[]
  scanned_ports?: string[]
  source_event_ids?: string[]
  window_start?: string
  window_end?: string
}

export interface AnomalyAlert {
  id: number
  host_id: string
  hostname: string
  alert_type: 'isolation_forest' | 'correlation'
  pattern_name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  anomaly_score: number
  top_metric: string
  top_value: number
  description: string
  trigger_context?: AnomalyTriggerContext
  status: 'open' | 'confirmed' | 'false_positive'
  resolved_by: string
  created_at: string
  updated_at: string
}

export interface AnomalyStats {
  total: number
  open: number
  critical: number
  by_type: { alert_type: string; count: number }[]
  by_pattern: { alert_type: string; count: number }[]
}

export interface ListAnomalyParams {
  page?: number
  page_size?: number
  host_id?: string
  alert_type?: string
  severity?: string
  status?: string
}

export const anomalyApi = {
  list: (params?: ListAnomalyParams) => {
    return apiClient.get<PaginatedResponse<AnomalyAlert>>('/anomalies', { params })
  },

  stats: () => {
    return apiClient.get<AnomalyStats>('/anomalies/stats')
  },

  resolve: (id: number, status: 'confirmed' | 'false_positive') => {
    return apiClient.put(`/anomalies/${id}/resolve`, { status })
  },
}
