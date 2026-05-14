import apiClient from './client'
import type {
  FIMPolicy,
  FIMEvent,
  FIMTask,
  FIMTaskHostStatus,
  FIMEventStats,
  FIMBaseline,
  FIMBaselineEntry,
  PaginatedResponse,
} from './types'

export const fimApi = {
  // === 策略管理 ===

  async listPolicies(params?: {
    page?: number
    page_size?: number
    name?: string
    enabled?: string
  }): Promise<PaginatedResponse<FIMPolicy>> {
    return apiClient.get<PaginatedResponse<FIMPolicy>>('/fim/policies', { params })
  },

  async getPolicy(policyId: string): Promise<FIMPolicy> {
    return apiClient.get<FIMPolicy>(`/fim/policies/${policyId}`)
  },

  async createPolicy(data: {
    name: string
    description?: string
    watch_paths: { path: string; level: string; comment: string }[]
    exclude_paths?: string[]
    check_interval_hours?: number
    target_type?: string
    target_config?: object
    enabled?: boolean
  }): Promise<FIMPolicy> {
    return apiClient.post<FIMPolicy>('/fim/policies', data)
  },

  async updatePolicy(policyId: string, data: {
    name?: string
    description?: string
    watch_paths?: { path: string; level: string; comment: string }[]
    exclude_paths?: string[]
    check_interval_hours?: number
    target_type?: string
    target_config?: object
    enabled?: boolean
  }): Promise<FIMPolicy> {
    return apiClient.put<FIMPolicy>(`/fim/policies/${policyId}`, data)
  },

  async deletePolicy(policyId: string): Promise<void> {
    await apiClient.delete(`/fim/policies/${policyId}`)
  },

  // === 任务管理 ===

  async listTasks(params?: {
    page?: number
    page_size?: number
    policy_id?: string
    status?: string
  }): Promise<PaginatedResponse<FIMTask>> {
    return apiClient.get<PaginatedResponse<FIMTask>>('/fim/tasks', { params })
  },

  async getTask(taskId: string): Promise<{ task: FIMTask; host_statuses: FIMTaskHostStatus[] }> {
    return apiClient.get<{ task: FIMTask; host_statuses: FIMTaskHostStatus[] }>(`/fim/tasks/${taskId}`)
  },

  async createTask(data: {
    policy_id: string
    target_type?: string
    target_config?: object
  }): Promise<FIMTask> {
    return apiClient.post<FIMTask>('/fim/tasks', data)
  },

  async runTask(taskId: string): Promise<FIMTask> {
    return apiClient.post<FIMTask>(`/fim/tasks/${taskId}/run`)
  },

  // === 事件查询 ===

  async listEvents(params?: {
    page?: number
    page_size?: number
    host_id?: string
    hostname?: string
    file_path?: string
    change_type?: string
    severity?: string
    category?: string
    status?: string
    task_id?: string
    date_from?: string
    date_to?: string
  }): Promise<PaginatedResponse<FIMEvent>> {
    return apiClient.get<PaginatedResponse<FIMEvent>>('/fim/events', { params })
  },

  async getEvent(eventId: string): Promise<FIMEvent> {
    return apiClient.get<FIMEvent>(`/fim/events/${eventId}`)
  },

  async getEventStats(days?: number): Promise<FIMEventStats> {
    return apiClient.get<FIMEventStats>('/fim/events/stats', { params: { days } })
  },

  async confirmEvent(eventId: string, data: { reason: string; update_baseline?: boolean }): Promise<void> {
    await apiClient.post(`/fim/events/${eventId}/confirm`, data)
  },

  async batchConfirmEvents(eventIds: string[], reason: string): Promise<{ confirmed: number }> {
    return apiClient.post<{ confirmed: number }>('/fim/events/batch-confirm', { event_ids: eventIds, reason })
  },

  // === 基线管理 ===

  async listBaselines(params?: {
    page?: number
    page_size?: number
    policy_id?: string
    host_id?: string
    status?: string
  }): Promise<PaginatedResponse<FIMBaseline>> {
    return apiClient.get<PaginatedResponse<FIMBaseline>>('/fim/baselines', { params })
  },

  async getBaseline(id: number, params?: {
    entry_page?: number
    entry_page_size?: number
  }): Promise<{ baseline: FIMBaseline; entries: FIMBaselineEntry[]; entry_total: number }> {
    return apiClient.get<{ baseline: FIMBaseline; entries: FIMBaselineEntry[]; entry_total: number }>(`/fim/baselines/${id}`, { params })
  },

  async approveBaseline(id: number): Promise<void> {
    await apiClient.post(`/fim/baselines/${id}/approve`)
  },

  async batchApproveBaselines(ids: number[]): Promise<{ approved: number }> {
    return apiClient.post<{ approved: number }>('/fim/baselines/batch-approve', { ids })
  },

  async rejectBaseline(id: number): Promise<void> {
    await apiClient.post(`/fim/baselines/${id}/reject`)
  },
}
