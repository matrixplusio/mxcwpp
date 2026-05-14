import apiClient from './client'

export interface RemediationTaskItem {
  id: number
  vulnId: number
  cveId: string
  hostId: string
  hostname: string
  ip: string
  component: string
  fixedVersion: string
  command: string
  status: string
  execOutput: string
  exitCode: number | null
  createdBy: string
  confirmedBy: string
  confirmedAt: string | null
  startedAt: string | null
  finishedAt: string | null
  createdAt: string
  updatedAt: string
}

export interface RemediationTaskStats {
  total?: number
  pending?: number
  confirmed?: number
  running?: number
  success?: number
  failed?: number
  cancelled?: number
  todaySuccess?: number
}

export const remediationTasksApi = {
  create: (vulnId: number, hostIds: string[]) => {
    return apiClient.post<{ created: number; tasks: RemediationTaskItem[] }>('/remediation-tasks', { vulnId, hostIds })
  },

  list: (params?: { page?: number; page_size?: number; status?: string; vuln_id?: string; host_id?: string }) => {
    return apiClient.get<{ total: number; items: RemediationTaskItem[] }>('/remediation-tasks', { params })
  },

  get: (id: number) => {
    return apiClient.get<RemediationTaskItem>(`/remediation-tasks/${id}`)
  },

  confirm: (id: number, command?: string) => {
    return apiClient.post(`/remediation-tasks/${id}/confirm`, command ? { command } : {})
  },

  cancel: (id: number) => {
    return apiClient.post(`/remediation-tasks/${id}/cancel`)
  },

  retry: (id: number, command?: string) => {
    return apiClient.post(`/remediation-tasks/${id}/retry`, command ? { command } : {})
  },

  batchCreate: (vulnIds: number[]) => {
    return apiClient.post<{ created: number }>('/remediation-tasks/batch', { vulnIds })
  },

  batchConfirm: (taskIds: number[]) => {
    return apiClient.post<{ confirmed: number }>('/remediation-tasks/batch-confirm', { taskIds })
  },

  batchRetry: (taskIds: number[]) => {
    return apiClient.post<{ retried: number }>('/remediation-tasks/batch-retry', { taskIds })
  },

  batchCancel: (taskIds: number[]) => {
    return apiClient.post<{ cancelled: number }>('/remediation-tasks/batch-cancel', { taskIds })
  },

  getStats: () => {
    return apiClient.get<RemediationTaskStats>('/remediation-tasks/stats')
  },
}
