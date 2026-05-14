import apiClient from './client'

export interface DetectionRule {
  id: number
  name: string
  expression: string
  severity: string
  mitreId: string
  category: string
  description: string
  dataTypes: string[]
  enabled: boolean
  createdAt: string
  updatedAt: string
}

export interface DetectionRuleListParams {
  page?: number
  page_size?: number
  keyword?: string
  severity?: string
  category?: string
  enabled?: string
}

export interface DetectionRuleStatistics {
  total: number
  enabled: number
  disabled: number
  severity: Record<string, number>
}

export interface CreateDetectionRuleRequest {
  name: string
  expression: string
  severity: string
  mitreId?: string
  category?: string
  description?: string
  dataTypes?: string[]
  enabled?: boolean
}

export const detectionRulesAPI = {
  list(params?: DetectionRuleListParams) {
    return apiClient.get<{ total: number; items: DetectionRule[] }>('/detection-rules', { params })
  },

  get(id: number) {
    return apiClient.get<DetectionRule>(`/detection-rules/${id}`)
  },

  create(data: CreateDetectionRuleRequest) {
    return apiClient.post<DetectionRule>('/detection-rules', data)
  },

  update(id: number, data: CreateDetectionRuleRequest) {
    return apiClient.put<DetectionRule>(`/detection-rules/${id}`, data)
  },

  delete(id: number) {
    return apiClient.delete(`/detection-rules/${id}`)
  },

  toggle(id: number) {
    return apiClient.post(`/detection-rules/${id}/toggle`)
  },

  getCategories() {
    return apiClient.get<string[]>('/detection-rules/categories')
  },

  getMitreIDs() {
    return apiClient.get<string[]>('/detection-rules/mitre-ids')
  },

  getStatistics() {
    return apiClient.get<DetectionRuleStatistics>('/detection-rules/statistics')
  },
}
