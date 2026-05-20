import apiClient from './client'
import type { PaginatedResponse } from './types'

// 通知类别
export type NotifyCategory = 'baseline_alert' | 'agent_offline' | 'virus_alert' | 'fim_alert' | 'edr_alert' | 'kube_alert' | 'vuln_bulletin'

export interface Notification {
  id: number
  name: string
  description?: string
  notify_category: NotifyCategory // 通知类别
  enabled: boolean
  type: 'lark' | 'webhook'
  severities: string[] // critical, high, medium, low（仅基线告警需要）
  scope: 'global' | 'host_tags' | 'business_line' | 'specified'
  scope_value?: string // JSON 字符串
  frontend_url?: string
  config: {
    webhook_url: string
    secret?: string
    user_notes?: string
  }
  created_at: string
  updated_at: string
}

export interface ScopeValueData {
  tags: string[]
  business_lines: string[]
  host_ids: string[]
}

export interface CreateNotificationRequest {
  name: string
  description?: string
  notify_category: NotifyCategory // 通知类别
  enabled?: boolean
  type: 'lark' | 'webhook'
  severities?: string[] // 仅基线告警需要
  scope: 'global' | 'host_tags' | 'business_line' | 'specified'
  scope_value: ScopeValueData
  frontend_url?: string
  config: {
    webhook_url: string
    secret?: string
    user_notes?: string
  }
}

export interface UpdateNotificationRequest {
  name?: string
  description?: string
  notify_category?: NotifyCategory
  enabled?: boolean
  type?: 'lark' | 'webhook'
  severities?: string[]
  scope?: 'global' | 'host_tags' | 'business_line' | 'specified'
  scope_value?: ScopeValueData
  frontend_url?: string
  config?: {
    webhook_url: string
    secret?: string
    user_notes?: string
  }
}

export interface TestNotificationRequest {
  type: 'lark' | 'webhook'
  config: {
    webhook_url: string
    secret?: string
    user_notes?: string
  }
  frontend_url?: string // 可选，用于测试跳转链接
  notification_id?: number // 可选，如果提供则使用完整的告警模板
  notify_category?: NotifyCategory // 可选，指定测试的通知类别
}

export const notificationsApi = {
  // 获取通知列表
  list: (params?: {
    page?: number
    page_size?: number
    enabled?: string
    keyword?: string
  }) => {
    return apiClient.get<PaginatedResponse<Notification>>('/notifications', { params })
  },

  // 获取通知详情
  get: (id: number) => {
    return apiClient.get<Notification>(`/notifications/${id}`)
  },

  // 创建通知
  create: (data: CreateNotificationRequest) => {
    return apiClient.post<Notification>('/notifications', data)
  },

  // 更新通知
  update: (id: number, data: UpdateNotificationRequest) => {
    return apiClient.put<Notification>(`/notifications/${id}`, data)
  },

  // 删除通知
  delete: (id: number) => {
    return apiClient.delete(`/notifications/${id}`)
  },

  // 测试通知
  test: (data: TestNotificationRequest) => {
    return apiClient.post('/notifications/test', data)
  },
}
