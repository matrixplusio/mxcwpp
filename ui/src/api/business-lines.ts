import apiClient from './client'
import type { PaginatedResponse } from './types'

export interface BusinessLine {
  id: number
  name: string
  code: string
  description?: string
  owner?: string
  contact?: string
  enabled: boolean
  host_count?: number
  created_at: string
  updated_at: string
}

export const businessLinesApi = {
  // 获取业务线列表
  list: (params?: {
    page?: number
    page_size?: number
    enabled?: string
    keyword?: string
  }) => {
    return apiClient.get<PaginatedResponse<BusinessLine>>('/business-lines', { params })
  },

  // 获取业务线详情
  get: (id: number) => {
    return apiClient.get<BusinessLine>(`/business-lines/${id}`)
  },

  // 创建业务线
  create: (data: {
    name: string
    code: string
    description?: string
    owner?: string
    contact?: string
    enabled?: boolean
  }) => {
    return apiClient.post<BusinessLine>('/business-lines', data)
  },

  // 更新业务线
  update: (id: number, data: {
    name?: string
    description?: string
    owner?: string
    contact?: string
    enabled?: boolean
  }) => {
    return apiClient.put<BusinessLine>(`/business-lines/${id}`, data)
  },

  // 删除业务线
  delete: (id: number) => {
    return apiClient.delete(`/business-lines/${id}`)
  },
}
