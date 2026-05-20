import apiClient from './client'

export interface RemediationPolicy {
  id: number
  name: string
  description: string
  targetType: string
  targetValue: string
  severityMin: string
  priorityMin: number
  autoConfirm: boolean
  maxParallel: number
  rolloutType: string
  canaryRatio: number
  enabled: boolean
  lastRunAt?: string
  createdBy: string
  createdAt: string
  updatedAt: string
}

export interface PolicyPreview {
  hostCount: number
  vulnCount: number
  taskCount: number
}

export interface PolicyExecution {
  id: number
  policyId: number
  status: string
  hostCount: number
  vulnCount: number
  taskCount: number
  errorMsg: string
  createdBy: string
  duration: number
  startedAt: string
  finishedAt?: string
}

export const remediationPoliciesApi = {
  list: () => {
    return apiClient.get<RemediationPolicy[]>('/remediation-policies')
  },

  create: (data: Partial<RemediationPolicy>) => {
    return apiClient.post<RemediationPolicy>('/remediation-policies', data)
  },

  get: (id: number) => {
    return apiClient.get<RemediationPolicy>(`/remediation-policies/${id}`)
  },

  update: (id: number, data: Partial<RemediationPolicy>) => {
    return apiClient.put(`/remediation-policies/${id}`, data)
  },

  delete: (id: number) => {
    return apiClient.delete(`/remediation-policies/${id}`)
  },

  execute: (id: number) => {
    return apiClient.post(`/remediation-policies/${id}/execute`)
  },

  preview: (id: number) => {
    return apiClient.post<PolicyPreview>(`/remediation-policies/${id}/preview`)
  },

  listExecutions: (id: number, page = 1, pageSize = 20) => {
    return apiClient.get<{ items: PolicyExecution[]; total: number; page: number }>(
      `/remediation-policies/${id}/executions`,
      { params: { page, pageSize } },
    )
  },
}
