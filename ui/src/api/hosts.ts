import apiClient from './client'
import axios from 'axios'
import type { Host, HostDetail, PaginatedResponse, BaselineScore, BaselineSummary, HostMetrics } from './types'

export type { Host } from './types'

export interface HostStatusDistribution {
  running: number
  abnormal: number
  offline: number
  not_installed: number
  uninstalled: number
}

export interface HostRiskDistribution {
  critical: number   // 存在严重风险基线的主机数
  high: number       // 存在高危风险基线的主机数
  medium: number     // 存在中危风险基线的主机数
  low: number        // 存在低危风险基线的主机数
}

export interface HostRiskStatistics {
  alerts: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
  vulnerabilities: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
  baseline: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
}

export interface HostPlugin {
  id?: number
  name: string
  version: string
  status: 'running' | 'stopped' | 'error' | 'not_installed' | 'updating' | 'dormant'
  start_time?: string
  updated_at?: string
  latest_version: string
  need_update: boolean
}

export const hostsApi = {
  // 获取主机列表
  list: (params?: {
    page?: number
    page_size?: number
    os_family?: string
    status?: string
    business_line?: string
    search?: string // 搜索关键词（主机名、host_id等）
    is_container?: boolean // 容器/主机类型筛选（废弃，使用 runtime_type）
    runtime_type?: 'vm' | 'docker' | 'k8s' // 运行环境类型筛选
  }) => {
    return apiClient.get<PaginatedResponse<Host>>('/hosts', { params })
  },

  // 获取主机详情
  get: (hostId: string) => {
    return apiClient.get<HostDetail>(`/hosts/${hostId}`)
  },

  // 获取主机基线得分
  getScore: (hostId: string) => {
    return apiClient.get<BaselineScore>(`/results/host/${hostId}/score`)
  },

  // 获取主机基线摘要
  getSummary: (hostId: string) => {
    return apiClient.get<BaselineSummary>(`/results/host/${hostId}/summary`)
  },

  // 获取主机状态分布
  getStatusDistribution: () => {
    return apiClient.get<HostStatusDistribution>('/hosts/status-distribution')
  },

  // 获取主机风险分布
  getRiskDistribution: () => {
    return apiClient.get<HostRiskDistribution>('/hosts/risk-distribution')
  },

  // 获取主机监控数据
  getMetrics: (hostId: string, params?: {
    start_time?: string
    end_time?: string
    range?: '1h' | '6h' | '24h'
  }) => {
    return apiClient.get<HostMetrics>(`/hosts/${hostId}/metrics`, { params })
  },

  // 更新主机标签
  updateTags: (hostId: string, tags: string[]) => {
    return apiClient.put(`/hosts/${hostId}/tags`, { tags })
  },

  // 获取主机风险统计
  getRiskStatistics: (hostId: string) => {
    return apiClient.get<HostRiskStatistics>(`/hosts/${hostId}/risk-statistics`)
  },

  // 更新主机业务线
  updateBusinessLine: (hostId: string, businessLine: string) => {
    return apiClient.put(`/hosts/${hostId}/business-line`, { business_line: businessLine })
  },

  // 获取主机插件列表
  getPlugins: (hostId: string) => {
    return apiClient.get<HostPlugin[]>(`/hosts/${hostId}/plugins`)
  },

  // 删除主机
  delete: (hostId: string) => {
    return apiClient.delete(`/hosts/${hostId}`)
  },

  // 批量删除主机
  batchDelete: (hostIds: string[], force = false) => {
    return apiClient.post<{ deleted: number; failed: number; skipped: number; total: number }>('/hosts/batch-delete', { host_ids: hostIds, force })
  },

  // 批量更新标签
  batchUpdateTags: (hostIds: string[], tags: string[], mode: 'append' | 'replace') => {
    return apiClient.post<{ updated: number; failed: number }>('/hosts/batch-update-tags', { host_ids: hostIds, tags, mode })
  },

  // 批量更新业务线
  batchUpdateBusinessLine: (hostIds: string[], businessLine: string) => {
    return apiClient.post<{ updated: number }>('/hosts/batch-update-business-line', { host_ids: hostIds, business_line: businessLine })
  },

  // 重启 Agent
  restartAgent: (hostIds?: string[]) => {
    return apiClient.post('/hosts/restart-agent', { host_ids: hostIds || [] })
  },

  // 获取 Agent 重启记录
  getRestartRecords: () => {
    return apiClient.get('/hosts/restart-records')
  },

  // 依赖安装（如 Tetragon）
  installDependency: (hostIds: string[], dependency: string, action: 'install' | 'uninstall' | 'status' = 'install', version?: string) => {
    return apiClient.post<{ message: string; data: Array<{ host_id: string; request_id?: string; status: string; error?: string }> }>('/hosts/dependency/install', {
      host_ids: hostIds,
      dependency,
      action,
      version,
    })
  },

  // 导出主机基线检查结果
  exportBaselineResults: async (hostId: string, format: 'markdown' | 'excel') => {
    const token = localStorage.getItem('mxcsec_token')
    const response = await axios.get(`/api/v1/results/host/${hostId}/export`, {
      params: { format },
      responseType: 'blob',
      headers: {
        Authorization: token ? `Bearer ${token}` : '',
      },
    })

    // 从响应头获取文件名
    const contentDisposition = response.headers['content-disposition']
    let filename = `baseline_report_${hostId}.${format === 'markdown' ? 'md' : 'xlsx'}`
    if (contentDisposition) {
      const matches = /filename="?([^"]+)"?/.exec(contentDisposition)
      if (matches && matches[1]) {
        filename = matches[1]
      }
    }

    // 创建下载链接
    const url = window.URL.createObjectURL(new Blob([response.data]))
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', filename)
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  },
}
