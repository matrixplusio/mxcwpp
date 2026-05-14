import apiClient from './client'
import type { FixTask, FixResult, FixTaskHostStatus, FixableItem, PaginatedResponse } from './types'

export const fixApi = {
  // 获取可修复项列表
  async getFixableItems(params: {
    host_ids?: string[]
    business_line?: string
    severities?: string[]
    page?: number
    page_size?: number
  }): Promise<PaginatedResponse<FixableItem>> {
    const response = await apiClient.get<PaginatedResponse<FixableItem>>('/fix/fixable-items', { params })
    return response
  },

  // 创建修复任务
  async createFixTask(data: {
    // 方式1：直接指定扫描结果的复合键（推荐）
    result_keys?: Array<{ task_id: string; host_id: string; rule_id: string }>
    // 方式2：指定主机和规则ID
    host_ids?: string[]
    rule_ids?: string[]
    severities?: string[]
    // 方式3：使用筛选条件
    use_filters?: boolean
    business_line?: string
  }): Promise<{ task_id: string }> {
    const response = await apiClient.post<{ task_id: string }>('/fix-tasks', data)
    return response
  },

  // 获取修复任务详情
  async getFixTask(taskId: string): Promise<FixTask> {
    const response = await apiClient.get<FixTask>(`/fix-tasks/${taskId}`)
    return response
  },

  // 获取修复任务列表
  async listFixTasks(params: {
    page?: number
    page_size?: number
    status?: string
  }): Promise<PaginatedResponse<FixTask>> {
    const response = await apiClient.get<PaginatedResponse<FixTask>>('/fix-tasks', { params })
    return response
  },

  // 获取修复任务结果
  async getFixResults(taskId: string, params?: {
    page?: number
    page_size?: number
    status?: string
  }): Promise<PaginatedResponse<FixResult>> {
    const response = await apiClient.get<PaginatedResponse<FixResult>>(`/fix-tasks/${taskId}/results`, { params })
    return response
  },

  // 取消修复任务
  async cancelFixTask(taskId: string): Promise<void> {
    await apiClient.post(`/fix-tasks/${taskId}/cancel`)
  },

  // 删除修复任务
  async deleteFixTask(taskId: string): Promise<void> {
    await apiClient.delete(`/fix-tasks/${taskId}`)
  },

  // 获取修复任务主机状态
  async getFixTaskHostStatus(taskId: string, params?: {
    page?: number
    page_size?: number
    status?: string
  }): Promise<PaginatedResponse<FixTaskHostStatus>> {
    const response = await apiClient.get<PaginatedResponse<FixTaskHostStatus>>(`/fix-tasks/${taskId}/host-status`, { params })
    return response
  },
}
