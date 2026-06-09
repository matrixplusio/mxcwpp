/**
 * 配置变更审批 API (P1-1 → P1-6)
 */
import apiClient from './client'
import type { ApiResponse } from './types'

const { get, post } = apiClient

export type ConfigChangeStatus = 'pending' | 'approved' | 'rejected' | 'cancelled' | 'applied' | 'failed'

export interface ConfigChangeRequest {
  id: number
  tenant_id: string
  target_table: string
  target_key: string
  old_value: string
  proposed_value: string
  reason: string
  status: ConfigChangeStatus
  requested_by: string
  approval_required_count: number
  approved_count: number
  approvers: string
  rejected_by: string
  reject_reason: string
  applied_at: string | null
  created_at: string
  updated_at: string
}

export interface CreateChangeRequest {
  target_table: string
  target_key: string
  proposed_value: string
  reason: string
}

export interface SensitivityInfo {
  key: string
  required_approval_count: number
  sensitive: boolean
}

export const ConfigChangeAPI = {
  list(params?: { status?: ConfigChangeStatus; target_table?: string }): Promise<ApiResponse<{ items: ConfigChangeRequest[]; total: number }>> {
    const qs = params ? '?' + new URLSearchParams(params as any).toString() : ''
    return get('/v2/config/change-requests' + qs)
  },

  get(id: number): Promise<ApiResponse<ConfigChangeRequest>> {
    return get(`/v2/config/change-requests/${id}`)
  },

  create(payload: CreateChangeRequest): Promise<ApiResponse<ConfigChangeRequest>> {
    return post('/v2/config/change-requests', payload)
  },

  approve(id: number): Promise<ApiResponse<ConfigChangeRequest>> {
    return post(`/v2/config/change-requests/${id}/approve`, {})
  },

  reject(id: number, reason: string): Promise<ApiResponse<ConfigChangeRequest>> {
    return post(`/v2/config/change-requests/${id}/reject`, { reason })
  },

  cancel(id: number): Promise<ApiResponse<ConfigChangeRequest>> {
    return post(`/v2/config/change-requests/${id}/cancel`, {})
  },

  getSensitivity(key: string): Promise<ApiResponse<SensitivityInfo>> {
    return get(`/v2/config/change-requests/sensitivity?key=${encodeURIComponent(key)}`)
  },
}
