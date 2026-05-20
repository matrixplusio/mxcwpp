import apiClient from './client'

export interface ImageScan {
  id: number
  image: string
  digest: string
  os: string
  totalVulns: number
  criticalCnt: number
  highCnt: number
  status: string
  errorMsg?: string
  scannedAt?: string
  createdAt: string
}

export interface ImageVulnerability {
  id: number
  imageScanId: number
  vulnId?: number
  cveId: string
  package: string
  version: string
  fixedVersion: string
  severity: string
  title: string
}

export const imageScansApi = {
  scan: (image: string) => {
    return apiClient.post<ImageScan>('/images/scan', { image })
  },

  list: (params?: { page?: number; page_size?: number }) => {
    return apiClient.get<{ total: number; items: ImageScan[] }>('/images/scans', { params })
  },

  get: (id: number) => {
    return apiClient.get<ImageScan>(`/images/scans/${id}`)
  },

  getVulns: (id: number) => {
    return apiClient.get<ImageVulnerability[]>(`/images/scans/${id}/vulns`)
  },

  // Registry
  listRegistries: () => {
    return apiClient.get<any[]>('/images/registries')
  },

  createRegistry: (data: { name: string; url: string; username?: string; password?: string; insecure?: boolean }) => {
    return apiClient.post('/images/registries', data)
  },

  updateRegistry: (id: number, data: { name?: string; url?: string; username?: string; password?: string; insecure?: boolean }) => {
    return apiClient.put(`/images/registries/${id}`, data)
  },

  deleteRegistry: (id: number) => {
    return apiClient.delete(`/images/registries/${id}`)
  },

  scanRegistry: (id: number) => {
    return apiClient.post(`/images/registries/${id}/scan`)
  },
}
