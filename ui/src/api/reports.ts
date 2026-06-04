import apiClient from './client'

// 报表统计数据接口
export interface ReportStats {
  // 主机统计
  hostStats: {
    total: number
    online: number
    offline: number
    byOsFamily: Record<string, number>
  }
  // 基线检查统计
  baselineStats: {
    totalChecks: number
    passed: number
    failed: number
    warning: number
    bySeverity: {
      critical: number
      high: number
      medium: number
      low: number
    }
    byCategory: Record<string, number>
  }
  // 策略统计
  policyStats: {
    total: number
    enabled: number
    disabled: number
    avgPassRate: number
  }
  // 任务统计
  taskStats: {
    total: number
    completed: number
    running: number
    failed: number
  }
}

// 时间序列数据
export interface TimeSeriesData {
  date: string
  value: number
}

// 基线得分趋势
export interface BaselineScoreTrend {
  dates: string[]
  scores: number[]
  passRates: number[]
}

// 检查结果趋势
export interface CheckResultTrend {
  dates: string[]
  passed: number[]
  failed: number[]
  warning: number[]
}

// 任务报告概要
export interface TaskReportSummary {
  task_id: string
  task_name: string
  policy_id: string
  policy_ids?: string[]
  policy_name: string
  policy_names?: string[]
  executed_at: string | null
  completed_at: string | null
  host_count: number
  rule_count: number
  status: string
}

// 类别统计（用于报告摘要）
export interface CategoryStats {
  category: string
  category_name: string
  total_checks: number
  passed_checks: number
  failed_checks: number
  pass_rate: number
}

// 任务报告统计
export interface TaskReportStatistics {
  total_checks: number
  passed_checks: number
  failed_checks: number
  warning_checks: number
  na_checks: number
  pass_rate: number
  by_severity: Record<string, number>
  by_category: Record<string, number>
}

// 主机检查明细
export interface HostCheckDetail {
  host_id: string
  hostname: string
  ip: string
  os_family: string
  passed_count: number
  failed_count: number
  warning_count: number
  na_count: number
  score: number
  status: string
  critical_fails: number
  high_fails: number
}

// 失败规则汇总
export interface FailedRuleSummary {
  rule_id: string
  title: string
  severity: string
  category: string
  affected_hosts: string[]
  affected_count: number
  fix_suggestion: string
  expected: string
}

// 任务报告
export interface TaskReport {
  summary: TaskReportSummary
  statistics: TaskReportStatistics
  host_details: HostCheckDetail[]
  failed_rules: FailedRuleSummary[]
}

// 主机任务详情
export interface HostTaskDetail {
  host: {
    host_id: string
    hostname: string
    ip: string
    os_family: string
    os_version: string
  }
  statistics: {
    total: number
    passed: number
    failed: number
    warning: number
    na: number
  }
  results: ScanResult[]
}

// 检查结果
export interface ScanResult {
  result_id: string
  host_id: string
  policy_id: string
  rule_id: string
  task_id: string
  status: string
  severity: string
  category: string
  title: string
  actual: string
  expected: string
  fix_suggestion: string
  checked_at: string
}

// Top 失败检查项
export interface TopFailedRule {
  rule_id: string
  title: string
  severity: string
  category: string
  affected_hosts: number
}

// Top 风险主机
export interface TopRiskHost {
  host_id: string
  hostname: string
  ip: string
  os_family: string
  score: number
  fail_count: number
  critical_count: number
  high_count: number
}

// 管理层报告元数据
export interface ExecutiveReportMeta {
  report_id: string
  report_title: string
  generated_at: string
  company_name: string
  baseline_type: string
  check_target: string
}

// 执行摘要
export interface ExecutiveSummary {
  overall_conclusion: string
  check_scope: string
  compliance_rate: number
  has_critical_risk: boolean
  has_high_risk: boolean
  conclusion_statement: string
  coverage_note: string
}

// 安全评分
export interface SecurityScore {
  score: number
  grade: string
  grade_color: string
  score_explanation: string
  security_note: string
}

// 风险项
export interface RiskItem {
  category: string
  description: string
  impact: string
  severity: string
  severity_label: string
  recommendation: string
  affected_count: number
}

// 合规与基线覆盖说明
export interface ComplianceCoverage {
  baseline_source: string
  covered_areas: string[]
  uncovered_areas: string[]
  improvement_note: string
}

// 管理建议
export interface ManagementRecommendation {
  overall_assessment: string
  action_suggestions: string[]
  disclaimer: string
}

// 管理层任务报告（完整版）
export interface ExecutiveTaskReport {
  meta: ExecutiveReportMeta
  summary: ExecutiveSummary
  task_info: TaskReportSummary
  statistics: TaskReportStatistics
  category_stats: CategoryStats[]  // 按类别统计（含通过率）
  security_score: SecurityScore
  host_details: HostCheckDetail[]
  risk_items: RiskItem[]
  failed_rules: FailedRuleSummary[]
  coverage: ComplianceCoverage
  recommendation: ManagementRecommendation
}

// ============================================================
// 分类报告 - 病毒查杀 / 漏洞管理 / 容器安全
// ============================================================

// 病毒查杀报告
export interface AntivirusReport {
  summary: {
    totalTasks: number
    totalThreats: number
    detectedThreats: number
    quarantinedThreats: number
    affectedHosts: number
  }
  severityDistribution: Record<string, number>
  threatTypeDistribution: Record<string, number>
  actionDistribution: Record<string, number>
  topThreats: Array<{
    threatName: string
    count: number
    severity: string
    affectedHosts: number
  }>
  topAffectedHosts: Array<{
    hostId: string
    hostname: string
    ip: string
    threatCount: number
  }>
}

// 漏洞管理报告
export interface VulnerabilityReport {
  summary: {
    totalVulns: number
    unpatchedVulns: number
    fixedVulns: number
    ignoredVulns: number
    affectedHosts: number
  }
  severityDistribution: Record<string, number>
  componentDistribution: Array<{ component: string; count: number }>
  topVulns: Array<{
    cveId: string
    severity: string
    cvssScore: number
    component: string
    affectedHosts: number
    status: string
  }>
  topAffectedHosts: Array<{
    hostId: string
    hostname: string
    ip: string
    vulnCount: number
    criticalCount: number
    highCount: number
  }>
}

// 容器安全报告
export interface KubeReport {
  summary: {
    totalAlarms: number
    pendingAlarms: number
    processedAlarms: number
    ignoredAlarms: number
    clusterCount: number
  }
  severityDistribution: Record<string, number>
  alarmTypeDistribution: Record<string, number>
  clusterDistribution: Array<{ clusterName: string; count: number }>
  topNamespaces: Array<{ namespace: string; clusterName: string; count: number }>
  topTargets: Array<{ target: string; namespace: string; count: number; severity: string }>
  baselineOverview: {
    totalChecks: number
    passed: number
    failed: number
    passRate: number
  }
  baselineAlerts: {
    active: number
    resolved: number
    ignored: number
  }
  baselineBySeverity: Record<string, number>
  baselineByCategory: Record<string, number>
}

// 分类报告查询参数
export interface CategoryReportParams {
  start_time?: string
  end_time?: string
}

// EDR 检测报告
export interface EDRReport {
  meta: {
    reportID: string
    period: string
    generatedAt: string
    onlineHosts: number
    totalRules: number
    enabledRules: number
  }
  summary: {
    totalAlerts: number
    activeAlerts: number
    resolvedAlerts: number
    ignoredAlerts: number
    affectedHosts: number
    totalStories: number
    highRiskStories: number
  }
  severityDistribution: Record<string, number>
  categoryDistribution: Array<{ category: string; count: number }>
  tacticDistribution: Record<string, number>
  topRules: Array<{ title: string; category: string; severity: string; count: number }>
  topHosts: Array<{ host_id: string; hostname: string; count: number }>
  topStories: Array<{
    story_id: string; host_id: string; hostname: string; phase: string
    severity: string; event_count: number; alert_count: number; risk_score: number
  }>
  suppressionStats: Array<{ reason: string; count: number }>
  trend: {
    prevPeriodAlerts: number
    growthPercent: number
    direction: 'up' | 'down' | 'stable'
  }
  rawEventStats: {
    totalEvents: number
    uniqueHosts: number
    eventsByType: Array<{ event_type: string; count: number }>
    eventsByHour: Array<{ hour: string; count: number }>
    topHostsByEvent: Array<{ host_id: string; hostname?: string; count: number }>
    topExe: Array<{ exe: string; count: number }>
    available: boolean
  }
  autoResponseStats: {
    networkBlocks: number
    hostIsolations: number
    processKills: number
    total: number
  }
  iocStats: {
    iocSnapshots: number
    memoryThreats: number
    topIOCTypes: Array<{ technique: string; count: number }>
  }
  ruleEfficacy: {
    totalRules: number
    enabledRules: number
    hitRules: number
    zeroHitRules: number
    hitRate: number
    topZeroHit: Array<{ id: number; name: string; category: string }>
  }
  improvements: string[]
}

// EDR 高管摘要报告
export interface EDRExecutiveReport {
  meta: { reportID: string; period: string; generatedAt: string }
  keyMetrics: {
    totalAlerts: number
    criticalAlerts: number
    highAlerts: number
    totalStories: number
    highRiskStories: number
    affectedHosts: number
    onlineHosts: number
    coverage: number
  }
  riskScore: number
  conclusion: string
  suggestions: string[]
}

// ============================================================
// Executive Report 类型（可导出 PDF 的专业报告）
// ============================================================

// 病毒查杀 Executive 报告
export interface AntivirusExecutiveReport {
  meta: {
    reportId: string
    reportTitle: string
    generatedAt: string
    companyName: string
    scanType: string
    checkTarget: string
  }
  summary: {
    overallConclusion: string
    threatOverview: string
    hasCriticalThreat: boolean
    hasHighThreat: boolean
  }
  taskInfo: {
    taskId: number
    taskName: string
    scanType: string
    hostCount: number
    scannedHosts: number
    threatCount: number
    startedAt: string
    finishedAt: string
  }
  statistics: {
    totalThreats: number
    detectedThreats: number
    quarantinedThreats: number
    deletedThreats: number
    ignoredThreats: number
    bySeverity: Record<string, number>
    byThreatType: Record<string, number>
    byAction: Record<string, number>
  }
  hostDetails: Array<{
    hostId: string
    hostname: string
    ip: string
    threatCount: number
    criticalCount: number
    highCount: number
  }>
  topThreats: Array<{
    threatName: string
    count: number
    severity: string
    affectedHosts: number
    filePaths: string[]
  }>
  recommendation: {
    overallAssessment: string
    actionSuggestions: string[]
    disclaimer: string
  }
}

// 漏洞管理 Executive 报告
export interface VulnerabilityExecutiveReport {
  meta: {
    reportId: string
    reportTitle: string
    generatedAt: string
    companyName: string
    reportPeriod: string
    checkTarget: string
  }
  summary: {
    overallConclusion: string
    vulnOverview: string
    hasCriticalVuln: boolean
    hasHighVuln: boolean
    complianceRate: number
  }
  statistics: {
    totalVulns: number
    unpatchedVulns: number
    fixedVulns: number
    ignoredVulns: number
    affectedHosts: number
    bySeverity: Record<string, number>
    byComponent: Array<{ component: string; count: number }>
  }
  hostDetails: Array<{
    hostId: string
    hostname: string
    ip: string
    vulnCount: number
    criticalCount: number
    highCount: number
  }>
  topVulns: Array<{
    cveId: string
    severity: string
    cvssScore: number
    component: string
    affectedHosts: number
    description: string
  }>
  recommendation: {
    overallAssessment: string
    actionSuggestions: string[]
    disclaimer: string
  }
}

// 容器安全 Executive 报告
export interface KubeExecutiveReport {
  meta: {
    reportId: string
    reportTitle: string
    generatedAt: string
    companyName: string
    reportPeriod: string
    checkTarget: string
  }
  summary: {
    overallConclusion: string
    alarmOverview: string
    baselineOverview: string
    hasCriticalAlarm: boolean
  }
  alarmStatistics: {
    totalAlarms: number
    pendingAlarms: number
    processedAlarms: number
    ignoredAlarms: number
    bySeverity: Record<string, number>
    byAlarmType: Record<string, number>
    byCluster: Array<{ clusterName: string; count: number }>
  }
  baselineStatistics: {
    totalChecks: number
    passed: number
    failed: number
    warning: number
    bySeverity: Record<string, number>
    byCategory: Record<string, number>
  }
  failedCheckDetails: Array<{
    checkId: string
    checkName: string
    category: string
    severity: string
    severityLabel: string
    description: string
    remediation: string
    clusterName: string
    affectedResources: Array<{ kind: string; name: string; namespace: string }> | null
  }>
  baselineRiskItems: Array<{
    checkId: string
    category: string
    description: string
    severity: string
    severityLabel: string
    remediation: string
    clusterName: string
  }>
  clusterDetails: Array<{
    clusterName: string
    alarmCount: number
    baselinePassRate: number
  }>
  topAlarms: Array<{
    namespace: string
    target: string
    alarmType: string
    count: number
  }>
  recommendation: {
    overallAssessment: string
    actionSuggestions: string[]
    disclaimer: string
  }
}

// 漏洞修复 Executive 报告
export interface RemediationExecutiveReport {
  meta: {
    reportId: string
    reportTitle: string
    generatedAt: string
    companyName: string
    reportPeriod: string
    checkTarget: string
  }
  summary: {
    overallConclusion: string
    remediationOverview: string
    hasFailedTasks: boolean
    hasUnpatchedVulns: boolean
    remediationRate: number
  }
  statistics: {
    totalTasks: number
    successTasks: number
    failedTasks: number
    pendingTasks: number
    cancelledTasks: number
    successRate: number
    totalVulns: number
    patchedVulns: number
    unpatchedVulns: number
    remediationRate: number
    mttrHours: number
    bySeverity: Array<{ severity: string; total: number; fixed: number; rate: number }>
    byComponent: Array<{ component: string; total: number; fixed: number }>
  }
  taskDetails: Array<{
    id: number
    cveId: string
    hostname: string
    ip: string
    component: string
    command: string
    status: string
    startedAt?: string
    finishedAt?: string
  }>
  hostDetails: Array<{
    hostId: string
    hostname: string
    ip: string
    total: number
    success: number
    failed: number
  }>
  recommendation: {
    overallAssessment: string
    actionSuggestions: string[]
    disclaimer: string
  }
}

// 已保存的报告记录
export interface GeneratedReportItem {
  id: number
  report_type: string
  title: string
  report_id: string
  period: string
  created_at: string
}

export const reportsApi = {
  // 获取报表统计数据
  getStats: async (params?: {
    start_time?: string
    end_time?: string
  }): Promise<ReportStats> => {
    return apiClient.get('/reports/stats', { params })
  },

  // 获取基线得分趋势
  getBaselineScoreTrend: async (params?: {
    host_id?: string
    policy_id?: string
    start_time?: string
    end_time?: string
    interval?: 'hour' | 'day' | 'week' | 'month'
  }): Promise<BaselineScoreTrend> => {
    return apiClient.get('/reports/baseline-score-trend', { params })
  },

  // 获取检查结果趋势
  getCheckResultTrend: async (params?: {
    host_id?: string
    policy_id?: string
    start_time?: string
    end_time?: string
    interval?: 'hour' | 'day' | 'week' | 'month'
  }): Promise<CheckResultTrend> => {
    return apiClient.get('/reports/check-result-trend', { params })
  },

  // 获取主机状态分布（用于图表）
  getHostStatusDistribution: async () => {
    return apiClient.get('/hosts/status-distribution')
  },

  // 获取主机风险分布（用于图表）
  getHostRiskDistribution: async () => {
    return apiClient.get('/hosts/risk-distribution')
  },

  // 获取任务报告
  getTaskReport: async (taskId: string): Promise<TaskReport> => {
    return apiClient.get(`/reports/task/${taskId}`)
  },

  // 获取管理层任务报告
  getExecutiveTaskReport: async (taskId: string): Promise<ExecutiveTaskReport> => {
    return apiClient.get(`/reports/task/${taskId}/executive`)
  },

  // 获取主机在任务中的详细检查结果
  getTaskHostDetail: async (taskId: string, hostId: string): Promise<HostTaskDetail> => {
    return apiClient.get(`/reports/task/${taskId}/host/${hostId}`)
  },

  // 获取 Top 失败检查项
  getTopFailedRules: async (limit?: number): Promise<TopFailedRule[]> => {
    return apiClient.get('/reports/top-failed-rules', { params: { limit } })
  },

  // 获取 Top 风险主机
  getTopRiskHosts: async (limit?: number): Promise<TopRiskHost[]> => {
    return apiClient.get('/reports/top-risk-hosts', { params: { limit } })
  },

  // 获取病毒查杀报告
  getAntivirusReport: async (params?: CategoryReportParams): Promise<AntivirusReport> => {
    return apiClient.get('/reports/antivirus', { params })
  },

  // 获取漏洞管理报告
  getVulnerabilityReport: async (params?: CategoryReportParams): Promise<VulnerabilityReport> => {
    return apiClient.get('/reports/vulnerability', { params })
  },

  // 获取容器安全报告
  getKubeReport: async (params?: CategoryReportParams): Promise<KubeReport> => {
    return apiClient.get('/reports/kube', { params })
  },

  // 获取 EDR 检测报告
  getEDRReport: async (params?: CategoryReportParams): Promise<EDRReport> => {
    return apiClient.get('/reports/edr', { params })
  },

  getEDRExecutiveReport: async (params: { start_time: string; end_time: string }): Promise<EDRExecutiveReport> => {
    return apiClient.get('/reports/edr/executive', { params })
  },

  // 服务端 PDF 导出（Gotenberg + Chromium）
  exportEDRPDF: async (params: { start_time: string; end_time: string; landscape?: boolean }) => {
    const res = await apiClient.get('/reports/edr/pdf', {
      params,
      responseType: 'blob',
    }) as unknown as Blob
    return res
  },

  exportAntivirusPDF: async (params: { start_time: string; end_time: string; landscape?: boolean }) => {
    const res = await apiClient.get('/reports/antivirus/pdf', {
      params,
      responseType: 'blob',
    }) as unknown as Blob
    return res
  },

  exportVulnPDF: async (params: { start_time: string; end_time: string; landscape?: boolean }) => {
    const res = await apiClient.get('/reports/vulnerability/pdf', {
      params,
      responseType: 'blob',
    }) as unknown as Blob
    return res
  },

  exportKubePDF: async (params: { start_time: string; end_time: string; landscape?: boolean }) => {
    const res = await apiClient.get('/reports/kube/pdf', {
      params,
      responseType: 'blob',
    }) as unknown as Blob
    return res
  },

  exportTaskPDF: async (taskId: string, params?: { landscape?: boolean }) => {
    const res = await apiClient.get(`/reports/task/${taskId}/pdf`, {
      params,
      responseType: 'blob',
    }) as unknown as Blob
    return res
  },

  // Executive 报告（可导出 PDF）
  getAntivirusExecutiveReport: async (taskId: number): Promise<AntivirusExecutiveReport> => {
    return apiClient.get(`/reports/antivirus/${taskId}/executive`)
  },

  getVulnerabilityExecutiveReport: async (params: { start_time: string; end_time: string }): Promise<VulnerabilityExecutiveReport> => {
    return apiClient.get('/reports/vulnerability/executive', { params })
  },

  getKubeExecutiveReport: async (params: { start_time: string; end_time: string }): Promise<KubeExecutiveReport> => {
    return apiClient.get('/reports/kube/executive', { params })
  },

  getRemediationExecutiveReport: async (params: { start_time: string; end_time: string }): Promise<RemediationExecutiveReport> => {
    return apiClient.get('/reports/remediation/executive', { params })
  },

  // 已保存的报告
  listGeneratedReports: async (reportType?: string): Promise<{ items: GeneratedReportItem[]; total: number }> => {
    return apiClient.get('/reports/generated', { params: { report_type: reportType } })
  },

  getGeneratedReport: async (id: number): Promise<any> => {
    return apiClient.get(`/reports/generated/${id}`)
  },

  deleteGeneratedReport: async (id: number): Promise<void> => {
    return apiClient.delete(`/reports/generated/${id}`)
  },
}
