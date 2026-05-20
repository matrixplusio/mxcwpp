import apiClient from './client'

export interface ScanSchedule {
  id: number
  name: string
  scanType: string
  cronExpr: string
  enabled: boolean
  lastRunAt?: string
  nextRunAt?: string
  createdBy: string
  createdAt: string
  updatedAt: string
}

export interface ScanScheduleExecution {
  id: number
  scheduleId: number
  scanType: string
  status: string
  errorMsg: string
  duration: number
  startedAt: string
  finishedAt?: string
}

export interface ExecutionVuln {
  id: number
  cveId: string
  severity: string
  cvssScore: number
  component: string
  affectedHosts: number
  description: string
}

export interface ExecutionHost {
  hostId: string
  hostname: string
  ip: string
  vulnCount: number
}

export interface ExecutionDetail {
  execution: ScanScheduleExecution
  scheduleName: string
  vulns: { items: ExecutionVuln[]; total: number; page: number }
  affectedHosts: ExecutionHost[]
}

export const scanSchedulesApi = {
  list: () => {
    return apiClient.get<ScanSchedule[]>('/vulnerabilities/schedules')
  },

  create: (data: { name: string; scanType: string; cronExpr: string }) => {
    return apiClient.post<ScanSchedule>('/vulnerabilities/schedules', data)
  },

  update: (id: number, data: Partial<ScanSchedule>) => {
    return apiClient.put(`/vulnerabilities/schedules/${id}`, data)
  },

  delete: (id: number) => {
    return apiClient.delete(`/vulnerabilities/schedules/${id}`)
  },

  toggle: (id: number) => {
    return apiClient.post(`/vulnerabilities/schedules/${id}/toggle`)
  },

  listExecutions: (id: number, page = 1, pageSize = 20) => {
    return apiClient.get<{ items: ScanScheduleExecution[]; total: number; page: number }>(
      `/vulnerabilities/schedules/${id}/executions`,
      { params: { page, pageSize } },
    )
  },

  getExecution: (execId: number, vulnPage = 1, vulnPageSize = 20) => {
    return apiClient.get<ExecutionDetail>(
      `/vulnerabilities/schedules/executions/${execId}`,
      { params: { vulnPage, vulnPageSize } },
    )
  },
}
