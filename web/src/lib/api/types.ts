export interface LoginRequest {
  username: string; password: string;
  captcha_id?: string; captcha_code?: string; device_id?: string;
}
export interface LoginUser { username: string; role: string; permissions?: string[]; read_only?: boolean; }
export interface LoginResponse { token: string; user: LoginUser; need_change_password?: boolean; }

export type Severity = "critical" | "high" | "medium" | "low";

export interface AlertTrendItem { date: string; critical: number; high: number; medium: number; low: number; }
export interface LatestAlert { id: string; title: string; severity: Severity; hostname: string; last_seen_at: string; }
export interface StorylineTop { story_id: string; title: string; risk_score: number; phase: string; hostname: string; }

export interface DashboardStats {
  securityScore: number;
  onlineAgents: number; offlineAgents: number;
  pendingAlerts: number; pendingVulnerabilities: number;
  baselineHardeningPercent: number;
  criticalAlerts: number; highAlerts: number; mediumAlerts: number; lowAlerts: number;
  alertTrend: AlertTrendItem[];
  latestAlerts: LatestAlert[];
  storylineTop: StorylineTop[];
  baselineHostPercent: number; hostAlertPercent: number; vulnHostPercent: number;
  detectionAlertPercent: number; virusHostPercent: number;
}

export interface Paged<T> { items: T[]; total: number; }

export type AlertSource = "baseline" | "detection" | "agent" | "vulnerability" | "fim" | "virus" | "kube";

export interface Alert {
  id: number;
  result_id: string;
  host_id: string;
  rule_id: string;
  policy_id: string;
  source: AlertSource;
  severity: Severity;
  risk_score: number;
  category: string;
  title: string;
  description?: string;
  actual?: string;
  expected?: string;
  fix_suggestion?: string;
  status: "active" | "resolved" | "ignored";
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string;
  resolved_by?: string;
  resolve_reason?: string;
  created_at: string;
  updated_at: string;
  host?: { host_id: string; hostname: string; ipv4: string[] };
  rule?: { rule_id: string; title: string };
}

export interface AlertStatistics {
  total: number; active: number; resolved: number; ignored: number;
  critical: number; high: number; medium: number; low: number;
}

export interface AlertWhitelist {
  id: number;
  name: string;
  rule_id: string;
  host_id: string;
  category: string;
  severity: string;
  exe: string;
  cmdline: string;
  source_ip_cidr: string;
  reason: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface AlertWhitelistSuggestion {
  id: number;
  signature: string;
  rule_id: string;
  rule_name: string;
  host_id: string;
  exe: string;
  cmdline: string;
  category: string;
  severity: string;
  hit_count: number;
  confidence: number;
  sample_alert_ids: string[] | null;
  resolve_reason_sample: string;
  status: "pending" | "adopted" | "dismissed";
  decided_by: string;
  decided_at: string | null;
  whitelist_id: number;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: number;
  incident_id: string;
  host_id: string;
  hostname: string;
  status: "active" | "investigating" | "resolved";
  severity: string;
  risk_score: number;
  tactics: string;
  tactic_count: number;
  alert_ids: string[] | null;
  alert_count: number;
  behavior_alert_count: number;
  storyline_ids: string[] | null;
  title: string;
  summary: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  resolved_by: string;
}

export interface User {
  id: number; username: string; email: string;
  role: string; status: "active" | "inactive";
  last_login?: string; created_at: string; updated_at: string;
}
export interface Permission { id: number; code: string; name: string; module: string; }
// 「模块 × 动作」权限矩阵：每模块含其支持的动作，动作码为 "module:action"。
export interface PermAction { code: string; name: string; }
export interface PermModule { code: string; name: string; actions: PermAction[]; }
export interface Role { code: string; name: string; permissions: string[]; read_only?: boolean; builtin?: boolean; }
export interface Notification {
  id: number; name: string; description?: string;
  notify_category: string; enabled: boolean;
  type: "lark" | "webhook"; severities: string[];
  scope: string; scope_value?: string;
  config: { webhook_url: string; secret?: string; user_notes?: string };
  created_at: string; updated_at: string;
}
export interface SiteConfig { site_name: string; site_logo: string; site_domain: string; backend_url: string; }
export interface RetentionPolicy { id: number; ch_table: string; display_name: string; description: string; retention_days: number; updated_by: string; updated_at: string; }
export interface FeatureFlag { id: number; key: string; value: string; default_value: string; description: string; updated_by: string; updated_at: string; }

export type AuditActorType = "user" | "system" | "agent";
export type AuditOutcome = "success" | "failure";

export interface AuditLog {
  id: number; actor_type: AuditActorType; username: string; action: string;
  outcome: AuditOutcome;
  resource_type: string; resource_id: string; target_name: string;
  path: string; ip: string; detail: string; change_detail: string;
  status_code: number; created_at: string;
}

// ===== 运维中心（operations）=====
export type ComponentCategory = "agent" | "plugin" | "dependency";

export interface Component {
  id: number; name: string; category: ComponentCategory;
  description: string; latest_version?: string; current_version?: string;
  version_count?: number; package_count?: number;
  created_by: string; created_at: string; updated_at?: string;
}
export interface ComponentPackage {
  id: number; version_id: number;
  os: string; arch: string; pkg_type: string;
  file_path: string; file_name: string;
  file_size: number; sha256: string; enabled: boolean;
  uploaded_by: string; uploaded_at: string;
}
export interface ComponentVersion {
  id: number; component_id: number; version: string; changelog: string;
  is_latest: boolean; packages_summary?: string;
  packages: ComponentPackage[];
  created_by: string; created_at: string;
}
export interface ComponentDetail {
  component: Component; versions: ComponentVersion[];
}
export interface PluginSyncStatus {
  name: string; type: string;
  config_version: string; config_sha256: string; config_enabled: boolean;
  download_urls: string[]; description: string;
  has_package: boolean; package_version: string; package_arch: string;
  status: string;
}
export interface ComponentPushRecord {
  id: number; component_name: string; version: string;
  target_type: string; target_hosts: string[] | null;
  status: string; progress: number;
  total_count: number; success_count: number; failed_count: number;
  failed_hosts: string[] | null; message: string;
  created_by: string; created_at: string; updated_at: string; completed_at?: string;
}

export interface InspectionSummary {
  total_hosts: number; online_hosts: number; offline_hosts: number;
  agent_outdated_count: number; plugin_error_count: number; plugin_outdated_count: number;
}
export interface InspectionHostPlugin { name: string; version: string; status: string; }
export interface InspectionHostItem {
  host_id: string; hostname: string; ipv4: string[];
  status: string; agent_version: string;
  agent_start_time: string; system_boot_time: string; last_heartbeat: string;
  os_family: string; os_version: string; arch: string;
  runtime_type: string; business_line: string;
  plugins: InspectionHostPlugin[];
}
export interface InspectionOverview {
  summary: InspectionSummary;
  latest_agent_version: string;
  latest_plugin_versions: Record<string, string>;
  hosts: InspectionHostItem[];
}

export interface Backup {
  id: number; type: string; status: string; scope: string;
  remark: string; file_size: number; created_by: string; created_at: string;
}
export interface BackupConfig { enabled: boolean; frequency: string; retention: number; }

export type MigrationStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export interface MigrationJob {
  id: number; source_url: string; source_user: string;
  scope: string[]; status: MigrationStatus; progress: number;
  current_table: string; total_records: number;
  created_count: number; skipped_count: number; failed_count: number;
  error: string; started_at?: string; finished_at?: string; created_at: string;
}
export interface MigrationTestResult { version: string; tables: Record<string, number>; }

export interface ReportStats {
  baselineStats: {
    totalChecks: number; passed: number; failed: number; warning: number;
    bySeverity: { critical: number; high: number; medium: number; low: number };
    byCategory: Record<string, number>;
  };
  hostStats: { total: number; online: number; offline: number; byOsFamily: Record<string, number> };
  policyStats: { total: number; enabled: number; disabled: number; avgPassRate: number };
  taskStats: { total: number; completed: number; failed: number; running: number };
}

// ===== 任务报告：后端无 /task-reports 端点；列表按报告类型走 /reports/{type} =====
export type TaskReportType = "antivirus" | "vulnerability" | "kube" | "edr";

export interface AntivirusTaskReport {
  summary: { totalTasks: number; totalThreats: number; detectedThreats: number; quarantinedThreats: number; affectedHosts: number };
  severityDistribution: Record<string, number>;
  threatTypeDistribution: Record<string, number>;
  actionDistribution: Record<string, number>;
  topThreats: { threatName: string; count: number; severity: string; affectedHosts: number }[];
  topAffectedHosts: { hostId: string; hostname: string; ip: string; threatCount: number }[];
}

export interface VulnerabilityTaskReport {
  summary: { totalVulns: number; unpatchedVulns: number; fixedVulns: number; ignoredVulns: number; affectedHosts: number };
  severityDistribution: Record<string, number>;
  componentDistribution: { component: string; count: number }[];
  topVulns: { cveId: string; severity: string; cvssScore: number; component: string; affectedHosts: number; status: string }[];
  topAffectedHosts: { hostId: string; hostname: string; ip: string; vulnCount: number; criticalCount: number; highCount: number }[];
}

export interface KubeTaskReport {
  summary: { totalAlarms: number; pendingAlarms: number; processedAlarms: number; ignoredAlarms: number; clusterCount: number };
  severityDistribution: Record<string, number>;
  alarmTypeDistribution: Record<string, number>;
  clusterDistribution: { clusterName: string; count: number }[];
  topNamespaces: { namespace: string; clusterName: string; count: number }[];
  topTargets: { target: string; namespace: string; count: number; severity: string }[];
  baselineOverview: { totalChecks: number; passed: number; failed: number; passRate: number };
  baselineAlerts: { active: number; resolved: number; ignored: number };
  baselineBySeverity: Record<string, number>;
  baselineByCategory: Record<string, number>;
}

export interface EdrTaskReport {
  meta: { reportID: string; period: string; generatedAt: string; onlineHosts: number; totalRules: number; enabledRules: number };
  summary: { totalAlerts: number; activeAlerts: number; resolvedAlerts: number; ignoredAlerts: number; affectedHosts: number; totalStories: number; highRiskStories: number };
  severityDistribution: Record<string, number>;
  tacticDistribution: Record<string, number>;
  topRules: { title: string; category: string; severity: string; count: number }[];
  topHosts: { host_id: string; hostname: string; count: number }[];
  ruleEfficacy: { totalRules: number; enabledRules: number; hitRules: number; zeroHitRules: number; hitRate: number };
}

export interface TaskReportMap {
  antivirus: AntivirusTaskReport;
  vulnerability: VulnerabilityTaskReport;
  kube: KubeTaskReport;
  edr: EdrTaskReport;
}

// ===== 资产中心（assets）=====
export type RuntimeType = "vm" | "docker" | "k8s";

export interface Host {
  host_id: string;
  hostname: string;
  os_family: string;
  os_version: string;
  kernel_version?: string;
  arch: string;
  ipv4: string[];
  ipv6?: string[];
  status: "online" | "offline";
  last_heartbeat: string;
  created_at: string;
  updated_at: string;
  baseline_score?: number;
  baseline_pass_rate?: number;
  tags?: string[];
  runtime_type?: RuntimeType;
  is_container?: boolean;
  container_id?: string;
  business_line?: string;
  agent_version?: string;
  agent_start_time?: string;
  system_boot_time?: string;
  last_active_time?: string;
  cpu_usage?: string;
  memory_usage?: string;
}

// 主机插件/组件版本（GET /hosts/:host_id/plugins）
export interface HostPlugin {
  id: number;
  name: string;
  version: string;
  status: string; // running / stopped / error / not_installed / ...
  start_time?: string;
  updated_at: string;
  latest_version: string;
  need_update: boolean;
}

export interface HostStatusDistribution {
  running: number;
  abnormal: number;
  offline: number;
  not_installed: number;
  uninstalled: number;
}
export interface HostRiskDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
}
export interface HostOSDistributionItem {
  os_family: string;
  major: string; // os_version 主版本号（"9.6" → "9"）
  count: number;
}

export interface AssetOverview {
  scope: "global" | "host";
  total_hosts: number;
  covered_hosts: number;
  uncovered_hosts: number;
  online_hosts: number;
  offline_hosts: number;
  business_line_count: number;
  coverage_rate: number;
  last_collected_at?: string;
}
export interface AssetStatistics {
  processes: number;
  ports: number;
  users: number;
  software: number;
  containers: number;
  apps: number;
  network_interfaces: number;
  volumes: number;
  kmods: number;
  services: number;
  crons: number;
}
export interface AssetTopItem {
  name: string;
  value: number;
}

export interface Process {
  id: string;
  host_id: string;
  pid: string;
  ppid: string;
  cmdline: string;
  exe: string;
  exe_hash?: string;
  container_id?: string;
  uid: string;
  gid: string;
  username?: string;
  groupname?: string;
  collected_at: string;
}
export interface Port {
  id: string;
  host_id: string;
  protocol: string;
  port: number;
  state?: string;
  pid?: string;
  process_name?: string;
  container_id?: string;
  collected_at: string;
}
export interface AssetUser {
  id: string;
  host_id: string;
  username: string;
  uid: string;
  gid: string;
  groupname?: string;
  home_dir: string;
  shell: string;
  comment?: string;
  has_password: boolean;
  collected_at: string;
}
export interface Software {
  id: string;
  host_id: string;
  name: string;
  version?: string;
  architecture?: string;
  package_type: string;
  vendor?: string;
  install_time?: string;
  collected_at: string;
}
export interface Container {
  id: string;
  host_id: string;
  container_id: string;
  container_name?: string;
  image?: string;
  image_id?: string;
  runtime?: string;
  status?: string;
  created_at?: string;
  collected_at: string;
}
export interface AppInfo {
  id: string;
  host_id: string;
  app_type: string;
  app_name?: string;
  version?: string;
  port?: number;
  process_id?: string;
  config_path?: string;
  data_path?: string;
  collected_at: string;
}
export interface NetInterface {
  id: string;
  host_id: string;
  interface_name: string;
  mac_address?: string;
  ipv4_addresses?: string[];
  ipv6_addresses?: string[];
  mtu?: number;
  state?: string;
  collected_at: string;
}
export interface Volume {
  id: string;
  host_id: string;
  device?: string;
  mount_point?: string;
  file_system?: string;
  total_size?: number;
  used_size?: number;
  available_size?: number;
  usage_percent?: number;
  collected_at: string;
}
export interface Kmod {
  id: string;
  host_id: string;
  module_name: string;
  size?: number;
  used_by?: number;
  state?: string;
  collected_at: string;
}
export interface Service {
  id: string;
  host_id: string;
  service_name: string;
  service_type?: string;
  status?: string;
  enabled?: boolean;
  description?: string;
  collected_at: string;
}
export interface Cron {
  id: string;
  host_id: string;
  user: string;
  schedule: string;
  command: string;
  cron_type?: string;
  enabled?: boolean;
  collected_at: string;
}

export interface BusinessLine {
  id: number;
  name: string;
  code: string;
  description?: string;
  owner?: string;
  contact?: string;
  enabled: boolean;
  host_count?: number;
  created_at: string;
  updated_at: string;
}

// ===== 系统监控（monitoring）=====
export type MonitorRange = "1h" | "6h" | "24h";

export interface HostMonitorOverview {
  cpu: number; memory: number; disk: number; load: number;
  cpuTrend: number; memoryTrend: number; diskTrend: number; loadTrend: number;
  agentCpu: number; agentMemMB: number; agentMemPercent: number;
}
export interface HostDiskPartition {
  mountPoint: string; filesystem: string;
  total: string; used: string; available: string; usagePercent: number;
}
export interface HostMonitorData {
  overview: HostMonitorOverview;
  cpu: { time: string; usage: number }[];
  memory: { time: string; usage: number }[];
  disk: { time: string; read: number; write: number }[];
  network: { time: string; inbound: number; outbound: number }[];
  partitions: HostDiskPartition[];
}

export type ServiceStatus = "healthy" | "warning" | "error";
export interface ServiceInfo {
  name: string; status: ServiceStatus;
  qps: number; cpu: number; memory: string;
  pid: string; uptime: string; version: string;
  detail?: string;
  p99LatencyMs?: number; errorRate?: number; connections?: number;
  queueLag?: number; goroutineCount?: number; gcPauseP99Ms?: number;
  dataSource?: string;
}
export type QpsPoint = { time: string } & Record<string, number>;
export interface ServiceConnection {
  service: string; protocol: string; address: string;
  activeConnections: number; totalConnections: number; status: string;
}
export interface ServiceMonitorData {
  services: ServiceInfo[];
  qps: QpsPoint[];
  latency: { time: string; p50: number; p95: number; p99: number }[];
  connections: ServiceConnection[];
}

// ===== 漏洞管理（vuln-management）=====
// 注：后端字段为 camelCase；列表分页响应为 Paged<T>（items=[] 空），部分列表为裸数组（schedules/policies/data-sources，空=[]，sbom 空=null）。

export interface VulnerabilityHostRef {
  hostId: string;
  hostname: string;
  ip: string;
  currentVersion?: string;
  status?: string;
}

// 漏洞列表 / 详情
export interface Vulnerability {
  id: number;
  cveId: string;
  osvId?: string;
  severity: string; // critical/high/medium/low/none
  cvssScore: number;
  component: string;
  description: string;
  affectedHosts: number;
  status: string; // unpatched/patched/ignored
  discoveredAt: string;
  currentVersion: string;
  fixedVersion?: string;
  referenceUrl?: string;
  cnvdId?: string;
  cnnvdId?: string;
  hasExploit?: boolean;
  inKev?: boolean;
  exploitRef?: string;
  priorityScore?: number;
  exposureScore?: number;
  vulnCategory?: string;
  restartAction?: string;
  cweId?: string;
  cweCategory?: string;
  assetType?: string;
  subscope?: string;
  fixOwner?: string;
  hostBinaryPath?: string;
  createdAt?: string;
  updatedAt?: string;
  hosts?: VulnerabilityHostRef[];
}
export interface VulnerabilityStats { total: number; critical: number; high: number; affectedHosts: number; }
// GET /vulnerabilities → { items, total, stats }
export interface VulnerabilityListResult { items: Vulnerability[]; total: number; stats: VulnerabilityStats; }

// 漏洞通报
export interface VulnBulletin {
  id: number;
  bulletinNo: string;
  vulnId: number;
  cveId: string;
  priority: string; // P0/P1/P2/P3
  component: string;
  severity: string;
  cvssScore: number;
  cvssVector: string;
  vulnType: string;
  attackVector: string;
  description: string;
  affectedAssets: number;
  affectedVersions: string;
  fixedVersion: string;
  fixSuggestion: string;
  workaround: string;
  patchAvailable: boolean;
  source: string;
  hasExploit: boolean;
  inKev: boolean;
  epssScore: number;
  exploitRef: string;
  status: string; // active/acknowledged/resolved/ignored
  notifiedAt?: string;
  acknowledgedAt?: string;
  acknowledgedBy?: string;
  resolvedAt?: string;
  resolvedBy?: string;
  resolveComment?: string;
  ignoredAt?: string;
  ignoredBy?: string;
  ignoreReason?: string;
  slaAckDeadline?: string;
  slaResolveDeadline?: string;
  slaBreached: boolean;
  notifyCount: number;
  lastNotifiedAt?: string;
  createdAt: string;
  updatedAt: string;
}
export interface VulnBulletinStatistics {
  active: number;
  sla_breached: number;
  by_priority: Record<string, number>;
  by_status: Record<string, number>;
}

// 扫描计划（裸数组）
export interface VulnScanSchedule {
  id: number;
  name: string;
  scanType: string; // sync_only/full_scan/incremental_scan
  cronExpr: string;
  enabled: boolean;
  lastRunAt?: string | null;
  nextRunAt?: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

// 修复报告（GET /vulnerabilities/stats/remediation）
export interface RemediationSeverityStat { severity: string; total: number; patched: number; unpatched: number; }
export interface RemediationHostStat { hostId: string; hostname: string; ip: string; total: number; patched: number; }
export interface RemediationReport {
  totalVulns: number;
  patchedVulns: number;
  unpatchedVulns: number;
  ignoredVulns: number;
  remediationRate: number;
  mttr: number;
  bySeverity: RemediationSeverityStat[];
  topUnpatched: RemediationHostStat[] | null;
}
export interface RemediationTrendItem { date: string; patched: number; discovered: number; }

// 修复任务
export interface RemediationTask {
  id: number;
  vulnId: number;
  cveId: string;
  hostId: string;
  hostname: string;
  ip: string;
  component: string;
  fixedVersion: string;
  command: string;
  status: string; // pending/confirmed/running/success/failed/cancelled
  execOutput: string;
  exitCode: number | null;
  createdBy: string;
  confirmedBy: string;
  confirmedAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  verifyStatus?: string;
  verifyMessage?: string;
  verifiedAt?: string | null;
  createdAt: string;
  updatedAt: string;
}
export interface RemediationTaskStats {
  total?: number;
  pending?: number;
  confirmed?: number;
  running?: number;
  success?: number;
  failed?: number;
  cancelled?: number;
  todaySuccess?: number;
}

// 修复策略（裸数组）
export interface RemediationPolicy {
  id: number;
  name: string;
  description: string;
  targetType: string;
  targetValue: string;
  severityMin: string;
  priorityMin: number;
  autoConfirm: boolean;
  maxParallel: number;
  rolloutType: string;
  canaryRatio: number;
  enabled: boolean;
  lastRunAt?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}
export interface RemediationPolicyPreview { hostCount: number; vulnCount: number; taskCount: number; }

// 漏洞库管理（cache）
export interface VulnDbStats {
  mode?: string;
  totalCount?: number;
  unpatchedCount?: number;
  patchedCount?: number;
  lastUpdated?: string;
}
export interface VulnDbImport {
  id: number;
  fileName: string;
  fileSize: number;
  status: string;
  importedCount: number;
  errorMsg?: string;
  createdBy: string;
  createdAt: string;
}

// 漏洞源管理（裸数组）
export interface VulnDataSource {
  id: number;
  name: string;
  displayName: string;
  region: "cn" | "global";
  category: "cn_official" | "os_advisory" | "cve_metadata" | "exploit";
  enabled: boolean;
  baseUrl: string;
  apiKeyEnv?: string;
  description: string;
  lastSyncAt?: string;
  lastStatus: "never" | "running" | "success" | "failed";
  lastError?: string;
  lastCount: number;
  lastDurationMs: number;
  createdAt: string;
  updatedAt: string;
}
export interface VulnDataSourceTestResult { reachable: boolean; http_status?: number; error?: string; }

// SBOM 导入（GET /sbom/projects → array | null）
export interface SbomProject {
  projectName: string;
  componentCount: number;
  vulnCount: number;
  criticalCount: number;
  highCount: number;
}

// ===== 容器集群（kube）=====
// 注：字段名镜像后端（camelCase）。列表均为 Paged<T>{ items, total }（空=[]），部分含 stats。

export interface KubeCluster {
  id: number;
  name: string;
  status: string; // running / abnormal / pending ...
  version: string;
  nodeCount: number;
  podCount: number;
  namespaceCount: number;
  healthScore: number;
  apiServer: string;
  remark?: string;
  auditToken?: string;
  gcpEnabled?: boolean;
  gcpProjectId?: string;
  gcpSubscription?: string;
  gcpLocation?: string;
  gcpClusterName?: string;
  createdAt: string;
  // getCluster 详情额外返回（列表接口无）
  summary?: { nodes: number; pods: number; namespaces: number; deployments: number; services: number; alarms: number };
  risks?: { alarms: number; baseline: number; events: number };
  uptime?: string;
  lastHeartbeat?: string;
  webhookURL?: string;
}

export interface KubeNode {
  name: string;
  status: string;
  roles: string;
  ip: string;
  os: string;
  cpuPercent: number;
  memoryPercent: number;
  podCount: number;
  kubeletVersion: string;
}

export interface KubePod {
  name: string;
  namespace: string;
  status: string;
  readyContainers: number;
  totalContainers: number;
  restarts: number;
  nodeName: string;
  podIp: string;
  age: string;
}

export interface KubeWorkload {
  name: string;
  type: string;
  namespace: string;
  readyReplicas: number;
  desiredReplicas: number;
  images: string;
  createdAt: string;
}
export interface KubeClusterStats { total: number; running: number; nodes: number; pods: number; }
export interface KubeClusterList { items: KubeCluster[]; total: number; stats: KubeClusterStats; }

export interface KubeAlarm {
  id: number;
  clusterName: string;
  alarmType: string;
  severity: Severity;
  title: string;
  message: string;
  status: string; // pending / processed / ignored
  createdAt: string;
}
export interface KubeAlarmStats { critical: number; high: number; medium: number; low: number; }
export interface KubeAlarmList { items: KubeAlarm[]; total: number; stats: KubeAlarmStats; }

export interface KubeEvent {
  id: number;
  clusterName: string;
  namespace: string;
  eventType: string;
  severity: Severity;
  title: string;
  message: string;
  status: string;
  createdAt: string;
}

export interface KubeAffectedResource { kind: string; name: string; namespace: string }
export interface KubeBaselineResult {
  id: number;
  checkId: string;
  checkName?: string;
  category: string;
  title: string;
  description?: string;
  severity: Severity;
  clusterName: string;
  result: string; // pass / fail / error
  remediation?: string;
  benchmark?: string;
  affectedResources?: KubeAffectedResource[];
  checkedAt: string;
}
export interface KubeBaselineStats { totalChecks: number; passed: number; failed: number; passRate: number; }
export interface KubeBaselineList { items: KubeBaselineResult[]; total: number; stats: KubeBaselineStats; }
export interface KubeBaselineTask {
  id: number;
  clusterId: number;
  clusterName: string;
  status: string; // running / done / failed
  total: number;
  passed: number;
  failed: number;
  errorCnt: number;
  passRate: number;
  startedAt: string;
  finishedAt?: string;
  createdAt: string;
}

export interface KubeBaselineAlert {
  id: number;
  checkId: string;
  checkName: string;
  category: string;
  severity: Severity;
  clusterName: string;
  status: string; // active / resolved / ignored
  lastSeenAt: string;
}
export interface KubeBaselineAlertStats { active: number; resolved: number; ignored: number; }
export interface KubeBaselineAlertList { items: KubeBaselineAlert[]; total: number; stats: KubeBaselineAlertStats; }

export interface KubeCheckConfig {
  resourceType: string;
  apiGroup: string;
  namespace: string;
  expression: string;
  matchPolicy: "any_match_fail" | "no_match_fail";
}
export interface KubeBaselineRule {
  id: number;
  checkId: string;
  checkName: string;
  category: string;
  severity: Severity;
  description: string;
  remediation: string;
  benchmark: string;
  checkConfig?: KubeCheckConfig | null;
  enabled: boolean;
  builtin: boolean;
  createdAt: string;
  updatedAt: string;
}
export interface KubeBaselineRuleStats { totalRules: number; enabled: number; disabled: number; builtin: number; }
export interface KubeBaselineRuleList { items: KubeBaselineRule[]; total: number; stats: KubeBaselineRuleStats; }

export interface KubeWhitelist {
  id: number;
  name: string;
  clusterId: string;
  clusterName: string;
  alarmTypes: string[];
  namespace: string;
  podPattern: string;
  hitCount: number;
  status: string; // enabled / disabled
  remark?: string;
  createdAt: string;
}

export interface KubeImageScan {
  id: number;
  image: string;
  clusterId?: number;
  source: string; // manual / cluster / registry
  digest: string;
  os: string;
  totalVulns: number;
  criticalCnt: number;
  highCnt: number;
  status: string; // pending / scanning / completed / failed
  errorMsg?: string;
  scannedAt?: string;
  createdAt: string;
}
export interface KubeImageRegistry {
  id: number;
  name: string;
  type: string; // basic / gcr / gar / acr
  url: string;
  username: string;
  insecure: boolean;
  imageCount: number;
  lastSyncAt?: string;
  createdAt: string;
}
export interface KubeImageVulnerability {
  id: number;
  imageScanId: number;
  cveId: string;
  package: string;
  version: string;
  fixedVersion: string;
  severity: Severity;
  title: string;
}

// 集群内扫描器（trivy-operator）状态机
export type KubeScannerState = "not_installed" | "installing" | "ready" | "degraded" | "uninstalling";
export interface KubeScannerStatus {
  state: KubeScannerState;
  operatorVersion: string;
  readyReplicas: number;
  webhookEnabled: boolean;
  lastSyncAt?: string;
  lastReportCount: number;
  lastError: string;
}
export interface KubeScannerPreflight {
  k8sVersion: string;
  canAutoInstall: boolean;
  namespaceExists: boolean;
  operatorExists: boolean;
  reason: string;
}

export type ServiceAlertSeverity = "critical" | "warning" | "info";
export type ServiceAlertStatus = "firing" | "resolved";
export interface ServiceAlert {
  id: string;
  createdAt: string;
  severity: ServiceAlertSeverity;
  service: string;
  message: string;
  status: ServiceAlertStatus;
  resolvedAt?: string;
}
export interface ServiceAlertStats { critical: number; warning: number; info: number; resolved: number; }
export interface ServiceAlertList { items: ServiceAlert[]; total: number; stats: ServiceAlertStats; }

// ===== 基线安全（baseline）=====
// 注：字段名镜像后端（snake_case）。/policies 返回 { items }（无 total）；其余列表为 Paged<T>{ items, total }。

// 基线检查策略
// 详细 OS 版本要求：每个 OS 族各自的版本区间
export interface OSRequirement {
  os_family: string;
  min_version?: string;
  max_version?: string;
}

export interface BaselinePolicy {
  id: string;
  name: string;
  version: string;
  description: string;
  os_family: string[];
  os_version: string;
  os_requirements?: OSRequirement[];
  enabled: boolean;
  group_id?: string;
  runtime_types?: RuntimeType[];
  rule_count?: number;
  created_at: string;
  updated_at: string;
}
// /policies 返回 { items }，无 total
export interface BaselinePolicyList { items: BaselinePolicy[]; }

// 基线规则（策略下的检查项）
export interface BaselineRule {
  rule_id: string;
  policy_id: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  enabled: boolean;
  builtin: boolean;
  runtime_types?: RuntimeType[];
  created_at: string;
  updated_at: string;
}

export interface BaselinePolicyStatistics {
  policy_id: string;
  rule_count: number;
  host_count: number;
  pass_rate: number;
  pass_count: number;
  fail_count: number;
  risk_count: number;
  last_check_time?: string;
}

// 策略组
export interface PolicyGroup {
  id: string;
  name: string;
  description: string;
  icon?: string;
  color?: string;
  sort_order: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  policy_count?: number;
  rule_count?: number;
  pass_rate?: number;
  host_count?: number;
}

// 基线扫描任务
export interface BaselineTask {
  task_id: string;
  name: string;
  type: string; // baseline_scan / manual / scheduled
  target_type: "all" | "host_ids" | "os_family";
  target_config: { host_ids?: string[]; os_family?: string[]; runtime_type?: RuntimeType };
  policy_id: string;
  policy_ids?: string[];
  rule_ids?: string[] | null;
  status: "created" | "pending" | "running" | "completed" | "partial" | "failed" | "cancelled";
  timeout_minutes?: number;
  retry_count?: number;
  max_retries?: number;
  matched_host_count?: number;
  total_host_count?: number;
  dispatched_host_count?: number;
  completed_host_count?: number;
  failed_reason?: string;
  created_at: string;
  executed_at?: string;
  completed_at?: string;
  updated_at: string;
}

// 任务检查项 - 不通过的主机（受影响资源/不通过原因）
export interface BaselineCheckAffectedHost {
  host_id: string;
  hostname: string;
  actual: string; // 实际值
}

// 任务检查项（按规则聚合多台主机的合规结果）
export interface BaselineTaskCheckItem {
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  description: string; // 说明
  expected: string; // 检查依据（期望值）
  remediation: string; // 修复建议
  result: "pass" | "fail" | "error" | "na"; // 合规结果
  host_total: number;
  host_passed: number;
  host_failed: number;
  host_error: number;
  affected_hosts: BaselineCheckAffectedHost[];
}

// 任务检查项明细响应
export interface BaselineTaskChecks {
  task: BaselineTask;
  total: number;
  passed: number;
  failed: number;
  error_cnt: number;
  pass_rate: number; // 0-1
  items: BaselineTaskCheckItem[];
}

// 可修复项（基线修复）
export interface BaselineFixItem {
  task_id: string;
  host_id: string;
  hostname: string;
  ip: string;
  business_line?: string;
  rule_id: string;
  title: string;
  category: string;
  severity: Severity;
  fix_suggestion?: string;
  fix_command?: string;
  actual?: string;
  expected?: string;
  has_fix: boolean;
}

// ===== 文件完整性（fim）=====
// 注：字段名镜像后端（snake_case）。所有列表均为 Paged<T>{ items, total }（空=[]）。
// 事件列表为精简结构（detail/trace_id）；事件详情为完整结构（change_detail/status 等）。

export type FimChangeType = "added" | "removed" | "changed";

export interface FimWatchPath {
  path: string;
  level: string; // NORMAL / CONTENT / PERMS
  comment: string;
}
export interface FimPolicy {
  tenant_id?: string;
  policy_id: string;
  name: string;
  description: string;
  watch_paths: FimWatchPath[];
  exclude_paths: string[];
  check_interval_hours: number;
  target_type: string; // all / host_ids / business_line
  target_config: { host_ids?: string[]; os_family?: string[] };
  escalation_timeout_min: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

// 事件列表项（GET /fim/events 精简结构）
export interface FimEvent {
  detected_at: string;
  host_id: string;
  hostname: string;
  file_path: string;
  change_type: FimChangeType;
  severity: Severity;
  category: string; // binary / config / auth / log / other
  detail: string;
  trace_id: string;
}

// 事件详情（GET /fim/events/{id} 完整结构）
export interface FimChangeDetail {
  size_before?: string;
  size_after?: string;
  hash_before?: string;
  hash_after?: string;
  mode_before?: string;
  mode_after?: string;
  hash_changed: boolean;
  permission_changed: boolean;
  owner_changed: boolean;
  attributes?: string;
}
export interface FimEventDetail {
  event_id: string;
  host_id: string;
  hostname: string;
  task_id: string;
  file_path: string;
  change_type: FimChangeType;
  change_detail: FimChangeDetail;
  severity: Severity;
  category: string;
  status: "pending" | "confirmed" | "escalated";
  confirmed_by?: string;
  confirmed_at?: string;
  confirm_reason?: string;
  alert_id?: number;
  detected_at: string;
  created_at: string;
}

export interface FimHostEventCount { host_id: string; hostname: string; count: number; }
export interface FimEventTrendPoint { date: string; count: number; }
export interface FimEventStats {
  total: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  added: number;
  removed: number;
  changed: number;
  by_category: Record<string, number>;
  top_hosts: FimHostEventCount[];
  trend: FimEventTrendPoint[];
}

export interface FimTask {
  tenant_id?: string;
  task_id: string;
  policy_id: string;
  status: "pending" | "running" | "completed" | "failed";
  target_type: string;
  target_config: { host_ids?: string[]; os_family?: string[] };
  dispatched_host_count: number;
  completed_host_count: number;
  total_events: number;
  created_at: string;
  executed_at?: string;
  completed_at?: string;
  updated_at: string;
}
export interface FimTaskHostStatus {
  id: number;
  task_id: string;
  host_id: string;
  hostname: string;
  status: "dispatched" | "completed" | "timeout" | "failed";
  total_entries: number;
  added_count: number;
  removed_count: number;
  changed_count: number;
  run_time_sec: number;
  error_message?: string;
  dispatched_at?: string;
  completed_at?: string;
}

export interface FimBaseline {
  id: number;
  policy_id: string;
  host_id: string;
  hostname: string;
  version: number;
  status: "pending" | "approved" | "outdated";
  entry_count: number;
  approved_by?: string;
  approved_at?: string;
  task_id: string;
  created_at: string;
  updated_at: string;
}
export interface FimBaselineEntry {
  id: number;
  baseline_id: number;
  file_path: string;
  sha256: string;
  file_size: number;
  file_mode: string;
  uid: number;
  gid: number;
  mtime: number;
}

// 修复任务（修复历史）
export interface BaselineFixHistory {
  task_id: string;
  host_ids: string[];
  rule_ids: string[];
  severities?: string[] | null;
  status: "pending" | "running" | "completed" | "failed";
  total_count: number;
  success_count: number;
  failed_count: number;
  progress: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
}

// ===== 病毒查杀（virus）=====
// 注：字段名镜像后端（camelCase）。列表均为 Paged<T>{ items, total }（空=[]）。

// 扫描任务
export interface VirusScanTask {
  id: number;
  name: string;
  scanType: string; // quick / full / custom
  scanPaths: string[];
  hostIds: string[];
  status: string; // pending / running / completed / failed / cancelled
  totalHosts: number;
  scannedHosts: number;
  threatCount: number;
  createdBy: string;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

// 扫描结果（恶意文件检测）
export interface VirusScanResult {
  id: number;
  taskId: number;
  hostId: string;
  hostname: string;
  ip: string;
  filePath: string;
  threatName: string;
  threatType: string;
  severity: string;
  fileHash: string;
  fileSize: number;
  action: string; // detected / quarantined / deleted / ignored
  detectedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface VirusStatistics {
  tasks: { total: number; running: number; completed: number };
  threats: { total: number; detected: number; quarantined: number; deleted: number; ignored: number };
  severity: { critical: number; high: number; medium: number; low: number };
  affectedHosts: number;
}

// 隔离文件
export interface QuarantineItem {
  id: number;
  scanResultId: number;
  hostId: string;
  hostname: string;
  ip: string;
  originalPath: string;
  quarantinePath: string;
  threatName: string;
  threatType: string;
  severity: string;
  fileHash: string;
  fileSize: number;
  filePermission: string;
  fileOwner: string;
  status: string; // quarantined / restored / deleted
  quarantinedBy: string;
  quarantinedAt: string;
  restoredAt: string | null;
  deletedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface QuarantineStatistics {
  total: number;
  quarantined: number;
  restored: number;
  deleted: number;
  totalSize: number;
  severity: { critical: number; high: number; medium: number; low: number };
  affectedHosts: number;
}

// ===== 威胁检测（detection）=====
// 注：全部 /api/v1（无 /v2）。列表分页响应统一 Paged<T>{ items, total }（空=[]）。
// detection-rules 列表用 { total, items }；threat-intel iocs 的 items 为 string[]。

// EDR 事件（GET /edr/events 精简结构）
export interface EdrEvent {
  timestamp: string;
  host_id: string;
  hostname: string;
  event_type: string; // process_exec / process_exit / file_open / file_write / tcp_connect ...
  data_type: number; // 3000=进程 3001=文件 3002=网络 3003=其他
  pid: string;
  ppid?: string;
  exe: string;
  cmdline?: string;
  parent_exe?: string;
  file_path: string;
  remote_addr: string;
  remote_port: string;
  local_addr?: string;
  local_port?: string;
  protocol?: string;
  uid?: string;
  gid?: string;
  return_code?: string;
}
export interface EdrEventStats {
  total: number;
  process_exec: number;
  file_open: number;
  network_connect: number;
  by_data_type: Record<number, number>;
  top_hosts: { host_id: string; hostname: string; count: number }[];
  top_exes: { exe: string; count: number }[];
  trend: { time: string; count: number }[];
}

// 检测规则
export interface DetectionRule {
  id: number;
  name: string;
  expression: string;
  severity: Severity;
  mitreId: string;
  category: string;
  description: string;
  dataTypes: string[];
  enabled: boolean;
  builtin?: boolean;
  userModified?: boolean;
  createdAt: string;
  updatedAt: string;
}
export interface DetectionRuleStats {
  total: number;
  enabled: number;
  disabled: number;
  severity: Record<string, number>;
}

// 威胁情报（IOC）
export interface ThreatIntelStats { ip: number; hash: number; domain: number; url: number; total: number; }
export interface ThreatIntelIocList { items: string[]; total: number; type: string; }
export interface ThreatIntelCheckResult { hit: boolean; type: string; value: string; }

// 威胁情报同步计划
export interface IntelSyncSchedule {
  id: number;
  name: string;
  cronExpr: string;
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  createdBy: string;
  createdAt: string;
}
export interface IntelSyncExecution {
  id: number;
  scheduleId: number;
  status: string; // running / success / failed
  errorMsg: string;
  iocCount: number;
  duration: number;
  startedAt: string;
  finishedAt: string | null;
}

// 攻击故事线
export interface Storyline {
  id: number;
  story_id: string;
  host_id: string;
  hostname: string;
  severity: Severity;
  status: "active" | "resolved" | "investigating";
  phase: string;
  summary: string;
  rule_names: string;
  event_count: number;
  alert_count: number;
  risk_score: number;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string;
  resolved_by?: string;
  created_at: string;
  updated_at: string;
}
export interface StorylineEvent {
  id: number;
  story_id: string;
  host_id: string;
  data_type: number;
  event_type: string;
  pid: string;
  exe: string;
  detail: string;
  rule_name: string;
  severity: string;
  timestamp: string;
  created_at: string;
}
export interface StorylineDetail {
  storyline: Storyline;
  events: StorylineEvent[];
  events_total: number;
  events_page: number;
  events_page_size: number;
}
export interface StorylineStats { total: number; active: number; critical_active: number; }

// 威胁狩猎
export interface HuntingQuery {
  id: number;
  name: string;
  description: string;
  mql: string;
  category: string;
  severity: Severity;
  owner: string;
  is_builtin: boolean;
  last_run_at?: string;
  last_hits: number;
  created_at: string;
  updated_at: string;
}
export interface HuntingResult {
  columns: string[];
  rows: Record<string, unknown>[];
  total_rows: number;
  elapsed_ms: number;
  sql: string;
}

// ML 异常检测
export interface AnomalyElevatedMetric { name: string; current: number; baseline: number; ratio: number; }
export interface AnomalyTriggerContext {
  elevated_metrics?: AnomalyElevatedMetric[];
  metric_snapshot?: Record<string, number>;
  suspicious_ips?: string[];
  suspicious_domains?: string[];
  sensitive_files?: string[];
  process_chain?: string[];
  scanned_ports?: string[];
  source_event_ids?: string[];
  window_start?: string;
  window_end?: string;
}
export interface AnomalyEvent {
  id: number;
  host_id: string;
  hostname: string;
  alert_type: "isolation_forest" | "correlation";
  pattern_name: string;
  severity: Severity;
  anomaly_score: number;
  top_metric: string;
  top_value: number;
  description: string;
  trigger_context?: AnomalyTriggerContext;
  status: "open" | "confirmed" | "false_positive";
  resolved_by: string;
  created_at: string;
  updated_at: string;
}
export interface AnomalyStats {
  total: number;
  open: number;
  critical: number;
  by_type: { alert_type: string; count: number }[];
  by_pattern: { alert_type: string; count: number }[];
}

// 行为基线（BDE）
export interface BdeBaseline {
  id: number;
  host_id: string;
  phase: "learning" | "active";
  samples: number;
  first_seen: string;
  created_at: string;
  updated_at: string;
}
export interface BdeBaselineStats {
  total_hosts: number;
  learning_hosts: number;
  active_hosts: number;
  open_alerts: number;
}
export interface BdeAlert {
  id: number;
  host_id: string;
  hostname: string;
  risk_score: number;
  metric: string;
  value: number;
  mean: number;
  stddev: number;
  z_score: number;
  status: "open" | "resolved" | "ignored";
  created_at: string;
  updated_at: string;
}
