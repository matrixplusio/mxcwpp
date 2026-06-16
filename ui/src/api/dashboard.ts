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

export interface IocByType {
  ip: number
  hash: number
  url: number
}

export interface StorylineTop {
  story_id: string
  title: string
  risk_score: number
  phase: string
  hostname: string
}

export interface RecentEvent {
  id: number
  event_type: string
  title: string
  hostname: string
  severity: string
  timestamp: string
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
  detectionAlertPercent?: number
  virusHostPercent?: number
  serviceStatus?: ServiceStatus
  alertTrend?: AlertTrendItem[]
  latestAlerts?: LatestAlert[]
  // SOC Dashboard 扩展
  securityScore?: number
  iocTotal?: number
  iocByType?: IocByType
  storylineCount?: number
  storylineTop?: StorylineTop[]
  recentEvents?: RecentEvent[]
  anomalyCount?: number
  criticalAlerts?: number
  highAlerts?: number
  mediumAlerts?: number
  lowAlerts?: number
}

export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    return apiClient.get('/dashboard/stats')
  },
}
