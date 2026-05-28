import apiClient from './client'

export interface VulnDataSource {
  id: number
  name: string
  displayName: string
  region: 'cn' | 'global'
  category: 'cn_official' | 'os_advisory' | 'cve_metadata' | 'exploit'
  enabled: boolean
  baseUrl: string
  apiKeyEnv?: string
  description: string
  lastSyncAt?: string
  lastStatus: 'never' | 'running' | 'success' | 'failed'
  lastError?: string
  lastCount: number
  lastDurationMs: number
  createdAt: string
  updatedAt: string
}

export interface TestConnectionResult {
  reachable: boolean
  http_status?: number
  error?: string
}

export const vulnDataSourcesApi = {
  list(): Promise<VulnDataSource[]> {
    return apiClient.get('/vuln-data-sources')
  },

  update(id: number, payload: { enabled?: boolean; baseUrl?: string }): Promise<VulnDataSource> {
    return apiClient.put(`/vuln-data-sources/${id}`, payload)
  },

  testConnection(id: number): Promise<TestConnectionResult> {
    return apiClient.post(`/vuln-data-sources/${id}/test`)
  },

  triggerSync(id: number): Promise<{ message: string }> {
    return apiClient.post(`/vuln-data-sources/${id}/sync`)
  },
}
