import apiClient from './client'
import type { Policy, PolicyStatistics } from './types'

export const policiesApi = {
  // 获取策略列表
  list: (params?: {
    os_family?: string
    enabled?: boolean
    group_id?: string
  }) => {
    return apiClient.get<{ items: Policy[] }>('/policies', { params })
  },

  // 获取策略详情
  get: (policyId: string) => {
    return apiClient.get<Policy>(`/policies/${policyId}`)
  },

  // 创建策略
  create: (data: {
    id: string
    name: string
    version?: string
    description?: string
    os_family?: string[]
    os_version?: string
    os_requirements?: Array<{ os_family: string; min_version?: string; max_version?: string }>
    enabled?: boolean
    group_id?: string
    runtime_types?: string[]
    rules?: Array<{
      rule_id: string
      category?: string
      title: string
      description?: string
      severity?: string
      check_config: any
      fix_config?: any
    }>
  }) => {
    return apiClient.post<Policy>('/policies', data)
  },

  // 更新策略
  update: (policyId: string, data: {
    name?: string
    version?: string
    description?: string
    os_family?: string[]
    os_version?: string
    os_requirements?: Array<{ os_family: string; min_version?: string; max_version?: string }>
    enabled?: boolean
    group_id?: string
    runtime_types?: string[]
    rules?: Array<{
      rule_id: string
      category?: string
      title: string
      description?: string
      severity?: string
      check_config: any
      fix_config?: any
    }>
  }) => {
    return apiClient.put<Policy>(`/policies/${policyId}`, data)
  },

  // 删除策略
  delete: (policyId: string) => {
    return apiClient.delete(`/policies/${policyId}`)
  },

  // 获取策略统计信息
  getStatistics: (policyId: string) => {
    return apiClient.get<PolicyStatistics>(`/policies/${policyId}/statistics`)
  },

  // 导出所有策略
  exportAll: () => {
    return apiClient.get<any>('/policies/export')
  },

  // 导出单个策略
  export: (policyId: string) => {
    return apiClient.get<any>(`/policies/${policyId}/export`)
  },

  // 导入策略
  import: (formData: FormData, mode: string = 'update') => {
    return apiClient.post<{
      imported: number
      updated: number
      skipped: number
      total: number
      errors?: string[]
    }>(`/policies/import?mode=${mode}`, formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
  },

  // 批量启用/禁用策略
  batchEnableDisable: (policyIds: string[], enabled: boolean) => {
    return apiClient.post<{ updated: number }>('/policies/batch/enable', {
      policy_ids: policyIds,
      enabled,
    })
  },

  // 批量删除策略
  batchDelete: (policyIds: string[]) => {
    return apiClient.post<{ deleted: number }>('/policies/batch/delete', {
      policy_ids: policyIds,
    })
  },

  // 批量导出策略
  batchExport: (policyIds: string[]) => {
    return apiClient.post<any>('/policies/batch/export', {
      policy_ids: policyIds,
    })
  },
}
