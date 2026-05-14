import apiClient from './client'

// 扫描任务
export interface AntivirusScanTask {
  id: number
  name: string
  scanType: string
  scanPaths: string[]
  hostIds: string[]
  status: string
  totalHosts: number
  scannedHosts: number
  threatCount: number
  createdBy: string
  startedAt: string | null
  finishedAt: string | null
  createdAt: string
  updatedAt: string
}

// 扫描结果
export interface AntivirusScanResult {
  id: number
  taskId: number
  hostId: string
  hostname: string
  ip: string
  filePath: string
  threatName: string
  threatType: string
  severity: string
  fileHash: string
  fileSize: number
  action: string
  detectedAt: string
  createdAt: string
  updatedAt: string
}

// 统计概览
export interface AntivirusStatistics {
  tasks: {
    total: number
    running: number
    completed: number
  }
  threats: {
    total: number
    detected: number
    quarantined: number
    deleted: number
    ignored: number
  }
  severity: {
    critical: number
    high: number
    medium: number
    low: number
  }
  affectedHosts: number
}

export interface ListTasksParams {
  page?: number
  page_size?: number
  keyword?: string
  status?: string
  scan_type?: string
}

export interface ListResultsParams {
  page?: number
  page_size?: number
  task_id?: number
  host_id?: string
  severity?: string
  threat_type?: string
  action?: string
  keyword?: string
}

// 病毒库同步记录
export interface SecurityDBSyncRecord {
  id: number
  dbType: string
  version: string
  status: string
  fileSize: number
  sha256: string
  errorMsg: string
  duration: number
  startedAt: string
  createdAt: string
}

export const antivirusApi = {
  // 扫描任务
  listTasks: (params?: ListTasksParams) => {
    return apiClient.get<{ total: number; items: AntivirusScanTask[] }>('/antivirus/tasks', { params })
  },

  getTask: (id: number) => {
    return apiClient.get<AntivirusScanTask>(`/antivirus/tasks/${id}`)
  },

  createTask: (data: {
    name: string
    scanType: string
    scanPaths?: string[]
    hostIds: string[]
  }) => {
    return apiClient.post<AntivirusScanTask>('/antivirus/tasks', data)
  },

  deleteTask: (id: number) => {
    return apiClient.delete(`/antivirus/tasks/${id}`)
  },

  cancelTask: (id: number) => {
    return apiClient.post(`/antivirus/tasks/${id}/cancel`)
  },

  // 扫描结果
  listResults: (params?: ListResultsParams) => {
    return apiClient.get<{ total: number; items: AntivirusScanResult[] }>('/antivirus/results', { params })
  },

  getResult: (id: number) => {
    return apiClient.get<AntivirusScanResult>(`/antivirus/results/${id}`)
  },

  quarantineResult: (id: number) => {
    return apiClient.post(`/antivirus/results/${id}/quarantine`)
  },

  ignoreResult: (id: number) => {
    return apiClient.post(`/antivirus/results/${id}/ignore`)
  },

  deleteFileResult: (id: number) => {
    return apiClient.post(`/antivirus/results/${id}/delete-file`)
  },

  // 统计
  getStatistics: () => {
    return apiClient.get<AntivirusStatistics>('/antivirus/statistics')
  },

  // 病毒库同步状态
  getVirusDBStatus: () => {
    return apiClient.get<SecurityDBSyncRecord | { status: string; message: string }>('/antivirus/virus-db/status')
  },

  getVirusDBHistory: (params?: { page?: number; page_size?: number }) => {
    return apiClient.get<{ total: number; items: SecurityDBSyncRecord[] }>('/antivirus/virus-db/history', { params })
  },

  triggerVirusDBSync: () => {
    return apiClient.post('/antivirus/virus-db/sync')
  },
}
