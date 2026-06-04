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
  // P5.6 复测字段
  execConfirmedBy?: string
  execConfirmedAt?: string | null
  verifyStatus?: string  // ''(legacy) / pending_user / verifying / verified / verify_failed / verify_blocked
  verifyMessage?: string
  verifiedAt?: string | null
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

  // P5.6: 修复任务执行后 user 手动确认 + 触发 pre-check 复测
  confirmExecuted: (id: number) => {
    return apiClient.post<{ taskId: number; requestId: string; verifyStatus: string; message: string }>(
      `/remediation-tasks/${id}/confirm-executed`,
    )
  },

  cancel: (id: number) => {
    return apiClient.post(`/remediation-tasks/${id}/cancel`)
  },

  retry: (id: number, command?: string) => {
    return apiClient.post(`/remediation-tasks/${id}/retry`, command ? { command } : {})
  },

  batchCreate: (vulnIds: number[]) => {
    return apiClient.post<{ created: number; vulnCount: number; hostCount: number; skipped: number }>('/remediation-tasks/batch', { vulnIds })
  },

  createForHost: (payload: { hostId: string; vulnIds?: number[]; allUnpatched?: boolean }) => {
    return apiClient.post<{ created: number; skipped: number; hostId: string; hostname: string }>('/remediation-tasks/host-batch', payload)
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
