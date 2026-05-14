import apiClient from './client'
import type {
  PaginatedResponse,
  AssetStatistics,
  AssetHistoryResult,
  AssetOverview,
  AssetCollectionStatus,
  AssetTopItem,
  AssetRelationsResult,
  Process,
  Port,
  AssetUser,
  Software,
  Container,
  App,
  NetInterface,
  Volume,
  Kmod,
  Service,
  Cron,
} from './types'

export const assetsApi = {
  // 获取进程列表
  listProcesses: (params?: {
    host_id?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Process>>('/assets/processes', { params })
  },

  // 获取端口列表
  listPorts: (params?: {
    host_id?: string
    protocol?: string // tcp/udp
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Port>>('/assets/ports', { params })
  },

  // 获取账户列表
  listUsers: (params?: {
    host_id?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<AssetUser>>('/assets/users', { params })
  },

  // 获取软件包列表
  listSoftware: (params?: {
    host_id?: string
    package_type?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Software>>('/assets/software', { params })
  },

  // 获取容器列表
  listContainers: (params?: {
    host_id?: string
    runtime?: string
    status?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Container>>('/assets/containers', { params })
  },

  // 获取应用列表
  listApps: (params?: {
    host_id?: string
    app_type?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<App>>('/assets/apps', { params })
  },

  // 获取网络接口列表
  listNetInterfaces: (params?: {
    host_id?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<NetInterface>>('/assets/network-interfaces', { params })
  },

  // 获取磁盘列表
  listVolumes: (params?: {
    host_id?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Volume>>('/assets/volumes', { params })
  },

  // 获取内核模块列表
  listKmods: (params?: {
    host_id?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Kmod>>('/assets/kmods', { params })
  },

  // 获取系统服务列表
  listServices: (params?: {
    host_id?: string
    service_type?: string
    status?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Service>>('/assets/services', { params })
  },

  // 获取定时任务列表
  listCrons: (params?: {
    host_id?: string
    user?: string
    cron_type?: string
    page?: number
    page_size?: number
  }) => {
    return apiClient.get<PaginatedResponse<Cron>>('/assets/crons', { params })
  },

  // 导出资产数据（CSV / JSON）
  exportAssets: (params: {
    type: string
    host_id?: string
    business_line?: string
    format?: 'csv' | 'json'
  }) => {
    return apiClient.download('/assets/export', params as Record<string, unknown>)
  },

  // 获取资产统计信息（用于资产指纹展示）
  getStatistics: (hostId?: string, businessLine?: string) => {
    const params = {
      host_id: hostId || undefined,
      business_line: businessLine || undefined,
    }
    return apiClient.get<AssetStatistics>('/assets/statistics', { params })
  },

  // 获取资产总览
  getOverview: (hostId?: string, businessLine?: string) => {
    const params = {
      host_id: hostId || undefined,
      business_line: businessLine || undefined,
    }
    return apiClient.get<AssetOverview>('/assets/overview', { params })
  },

  // 获取资产历史快照
  getHistory: (params?: {
    host_id?: string
    business_line?: string
    days?: number
    limit?: number
  }) => {
    return apiClient.get<AssetHistoryResult>('/assets/history', { params })
  },

  // 获取资产采集状态
  getCollectionStatus: (hostId?: string, businessLine?: string) => {
    const params = {
      host_id: hostId || undefined,
      business_line: businessLine || undefined,
    }
    return apiClient.get<AssetCollectionStatus>('/assets/status', { params })
  },

  // 获取主机资产关系视图
  getRelations: (params: {
    host_id?: string
    business_line?: string
    keyword?: string
    limit?: number
    all?: boolean
  }) => {
    return apiClient.get<AssetRelationsResult>('/assets/relations', { params })
  },

  // 获取资产 TopN 聚合
  getTopN: (params: {
    type: string
    host_id?: string
    business_line?: string
    limit?: number
  }) => {
    return apiClient.get<{ items: AssetTopItem[] }>('/assets/top', { params })
  },
}
