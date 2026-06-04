import apiClient from './client'
import type { EDREvent, EDREventStats, PaginatedResponse } from './types'
import type { AxiosRequestConfig } from 'axios'

export const edrApi = {
  // === 事件查询 ===

  async listEvents(
    params?: {
      page?: number
      page_size?: number
      host_id?: string
      hostname?: string
      event_type?: string
      data_type?: number
      exe?: string
      cmdline?: string
      file_path?: string
      remote_addr?: string
      pid?: string
      keyword?: string
      date_from?: string
      date_to?: string
    },
    // 透传 AbortController.signal 等 axios 配置：支持页面 cancel 长查询
    config?: AxiosRequestConfig,
  ): Promise<PaginatedResponse<EDREvent>> {
    return apiClient.get<PaginatedResponse<EDREvent>>('/edr/events', { params, ...config })
  },

  async getEventStats(hours?: number): Promise<EDREventStats> {
    return apiClient.get<EDREventStats>('/edr/events/stats', { params: { hours } })
  },
}
