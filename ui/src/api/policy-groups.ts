import apiClient from './client'
import type { PolicyGroup, PolicyGroupStatistics, PaginatedResponse } from './types'

export const policyGroupsApi = {
  // 获取策略组列表
  list: (params?: { with_policies?: boolean }) => {
    return apiClient.get<PaginatedResponse<PolicyGroup>>('/policy-groups', { params })
  },

  // 获取策略组详情
  get: (id: string, params?: { with_policies?: boolean }) => {
    return apiClient.get<PolicyGroup>(`/policy-groups/${id}`, { params })
  },

  // 获取策略组统计信息
  getStatistics: (id: string) => {
    return apiClient.get<PolicyGroupStatistics>(`/policy-groups/${id}/statistics`)
  },

  // 创建策略组
  create: (data: {
    id?: string
    name: string
    description?: string
    icon?: string
    color?: string
    sort_order?: number
    enabled?: boolean
  }) => {
    return apiClient.post<PolicyGroup>('/policy-groups', data)
  },

  // 更新策略组
  update: (id: string, data: {
    name?: string
    description?: string
    icon?: string
    color?: string
    sort_order?: number
    enabled?: boolean
  }) => {
    return apiClient.put<PolicyGroup>(`/policy-groups/${id}`, data)
  },

  // 删除策略组
  delete: (id: string) => {
    return apiClient.delete(`/policy-groups/${id}`)
  },
}
