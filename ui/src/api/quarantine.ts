import apiClient from './client'
import type { PaginatedResponse } from './types'

export interface QuarantineFile {
  id: number
  scanResultId: number
  hostId: string
  hostname: string
  ip: string
  originalPath: string
  quarantinePath: string
  threatName: string
  threatType: string
  severity: string
  fileHash: string
  fileSize: number
  filePermission: string
  fileOwner: string
  status: string // quarantined, restored, deleted
  quarantinedBy: string
  quarantinedAt: string
  restoredAt: string | null
  deletedAt: string | null
  createdAt: string
  updatedAt: string
}

export interface QuarantineStatistics {
  total: number
  quarantined: number
  restored: number
  deleted: number
  totalSize: number
  severity: {
    critical: number
    high: number
    medium: number
    low: number
  }
  affectedHosts: number
}

export const quarantineApi = {
  list: (params?: {
    page?: number
    page_size?: number
    keyword?: string
    status?: string
    severity?: string
    threat_type?: string
    host_id?: string
  }) => {
    return apiClient.get<PaginatedResponse<QuarantineFile>>('/quarantine/files', { params })
  },

  get: (id: number) => {
    return apiClient.get<QuarantineFile>(`/quarantine/files/${id}`)
  },

  restore: (id: number) => {
    return apiClient.post(`/quarantine/files/${id}/restore`)
  },

  delete: (id: number) => {
    return apiClient.delete(`/quarantine/files/${id}`)
  },

  batchDelete: (ids: number[]) => {
    return apiClient.post<{ deleted: number }>('/quarantine/files/batch-delete', { ids })
  },

  getStatistics: () => {
    return apiClient.get<QuarantineStatistics>('/quarantine/statistics')
  },
}
