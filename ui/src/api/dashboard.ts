import apiClient from './client'

export interface BaselineRisk {
  name: string
  critical: number
  high: number
  medium: number
  low: number
}

export interface ServiceStatus {
  database: 'healthy' | 'warning' | 'error'
  agentcenter: 'healthy' | 'warning' | 'error'
  manager: 'healthy' | 'warning' | 'error'
  // 基线检查插件在 Agent 端运行，Server 端无法直接检查其状态
}

export interface AlertTrendItem {
  date: string
  critical: number
  high: number
  medium: number
  low: number
}

export interface LatestAlert {
  id: number
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  hostname: string
  last_seen_at: string
}

export interface DashboardStats {
  hosts: number
  clusters: number
  containers: number
  onlineAgents: number
  offlineAgents: number
  onlineAgentsChange?: number
  offlineAgentsChange?: number
  pendingAlerts: number
  pendingVulnerabilities: number
  vulnDbUpdateTime: string
  hotPatchCount?: number
  baselineFailCount: number
  baselineHardeningPercent: number
  baselineRisks?: BaselineRisk[]
  avgCpuUsage?: number
  avgCpuUsageChange?: number
  avgMemoryUsage?: number
  avgMemoryUsageChange?: number
  hostAlertPercent?: number
  vulnHostPercent?: number
  baselineHostPercent?: number
  runtimeAlertPercent?: number
  virusHostPercent?: number
  serviceStatus?: ServiceStatus
  alertTrend?: AlertTrendItem[]
  latestAlerts?: LatestAlert[]
}

export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    return apiClient.get('/dashboard/stats')
  },
}
