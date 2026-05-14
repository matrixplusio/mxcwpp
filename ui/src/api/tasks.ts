import apiClient from './client'
import type { ScanTask, PaginatedResponse } from './types'

export const tasksApi = {
  // 获取任务列表
  list: (params?: {
    page?: number
    page_size?: number
    status?: string
    policy_id?: string
  }) => {
    return apiClient.get<PaginatedResponse<ScanTask>>('/tasks', { params })
  },

  // 获取任务详情
  get: (taskId: string) => {
    return apiClient.get<ScanTask>(`/tasks/${taskId}`)
  },

  // 创建任务
  create: (data: {
    name: string
    type: 'manual' | 'scheduled'
    targets: {
      type: 'all' | 'host_ids' | 'os_family'
      host_ids?: string[]
      os_family?: string[]
      runtime_type?: 'vm' | 'docker' | 'k8s' // 运行时类型
    }
    policy_id?: string    // 兼容旧版本：单策略
    policy_ids?: string[] // 新版本：多策略
    rule_ids?: string[]
    schedule?: any
  }) => {
    return apiClient.post<ScanTask>('/tasks', data)
  },

  // 执行任务
  run: (taskId: string) => {
    return apiClient.post<ScanTask>(`/tasks/${taskId}/run`)
  },

  // 取消任务
  cancel: (taskId: string) => {
    return apiClient.post<ScanTask>(`/tasks/${taskId}/cancel`)
  },

  // 删除任务
  delete: (taskId: string) => {
    return apiClient.delete(`/tasks/${taskId}`)
  },

  // 获取任务主机执行状态
  getHostStatus: (taskId: string) => {
    return apiClient.get<{
      task_id: string
      hosts: Array<{
        id: number
        task_id: string
        host_id: string
        hostname: string
        status: 'dispatched' | 'completed' | 'timeout' | 'failed'
        dispatched_at: string
        completed_at?: string
        error_message?: string
        created_at: string
        updated_at: string
      }>
    }>(`/tasks/${taskId}/host-status`)
  },
}
