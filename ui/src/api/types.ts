// API 响应类型定义

export interface ApiResponse<T = any> {
  code: number
  message?: string
  data: T
}

export interface PaginatedResponse<T> {
  total: number
  items: T[]
}

export interface AssetStatistics {
  processes: number
  ports: number
  users: number
  software: number
  containers: number
  apps: number
  network_interfaces: number
  volumes: number
  kmods: number
  services: number
  crons: number
}

export interface AssetCollectorStatus {
  version?: string
  config_enabled: boolean
  package_uploaded: boolean
  package_path?: string
  host_status?: string
  host_version?: string
}

export interface AssetCollectionStatus {
  host_id?: string
  scope: 'global' | 'host'
  has_data: boolean
  last_collected_at?: string
  level?: 'warning' | 'error'
  message?: string
  collector: AssetCollectorStatus
}

export interface AssetOverview {
  scope: 'global' | 'host'
  total_hosts: number
  covered_hosts: number
  uncovered_hosts: number
  online_hosts: number
  offline_hosts: number
  business_line_count: number
  coverage_rate: number
  last_collected_at?: string
}

export interface AssetHistoryPoint {
  timestamp: string
  total: number
  delta_total: number
  statistics: AssetStatistics
}

export interface AssetHistoryResult {
  scope: 'global' | 'host'
  host_id?: string
  business_line?: string
  total_snapshots: number
  latest_collected_at?: string
  points: AssetHistoryPoint[]
}

export interface AssetTopItem {
  name: string
  value: number
}

export interface AssetRelationProcess {
  pid: string
  ppid: string
  exe: string
  cmdline: string
  username: string
  container_id?: string
  collected_at?: string
}

export interface AssetRelationHost {
  host_id: string
  hostname: string
  ipv4?: string[]
  business_line?: string
  status?: string
  agent_version?: string
  runtime_type?: string
  last_heartbeat?: string
}

export interface AssetRelationPort {
  protocol: string
  port: number
  state: string
}

export interface AssetRelationApp {
  app_type: string
  app_name: string
  version: string
  port: number
  config_path: string
}

export interface AssetRelationSoftware {
  name: string
  version: string
  package_type: string
  architecture: string
}

export interface AssetRelationContainer {
  container_id: string
  container_name: string
  image: string
  runtime: string
  status: string
}

export interface AssetRelationService {
  service_name: string
  service_type: string
  status: string
  enabled: boolean
}

export interface AssetRelationConfidence {
  level: 'exact' | 'mixed' | 'heuristic'
  matched_by: string[]
}

export interface AssetRelationVulnerability {
  cve_id: string
  severity: string
  component: string
  status: string
  current_version?: string
  fixed_version?: string
}

export interface AssetRelationChange {
  event_id: string
  file_path: string
  change_type: string
  severity: string
  category?: string
  detected_at: string
}

export interface AssetRelationRiskSummary {
  exposed_port_count: number
  vulnerability_count: number
  fim_change_count: number
  last_changed_at?: string
}

export interface AssetRelationItem {
  host: AssetRelationHost
  process: AssetRelationProcess
  ports?: AssetRelationPort[]
  apps?: AssetRelationApp[]
  software?: AssetRelationSoftware[]
  services?: AssetRelationService[]
  container?: AssetRelationContainer
  confidence: AssetRelationConfidence
  risks: AssetRelationRiskSummary
  vulnerabilities?: AssetRelationVulnerability[]
  recent_changes?: AssetRelationChange[]
  related_kinds: string[]
  relation_score: number
}

export interface AssetRelationsResult {
  scope: 'global' | 'host'
  host_id?: string
  business_line?: string
  total: number
  items: AssetRelationItem[]
}

export interface VulnerabilityHost {
  id: number
  vulnId: number
  hostId: string
  hostname: string
  ip: string
  currentVersion: string
  status: string
  createdAt: string
  updatedAt: string
}

export interface Vulnerability {
  id: number
  cveId: string
  osvId?: string
  severity: string
  cvssScore: number
  component: string
  description: string
  affectedHosts: number
  status: string
  discoveredAt: string
  currentVersion: string
  fixedVersion?: string
  referenceUrl?: string
  createdAt?: string
  updatedAt?: string
  hosts?: VulnerabilityHost[]
}

export interface VulnerabilityStats {
  total: number
  critical: number
  high: number
  affectedHosts: number
}

export interface VulnerabilityListResult {
  total: number
  items: Vulnerability[]
  stats: VulnerabilityStats
}

// 运行时类型
export type RuntimeType = 'vm' | 'docker' | 'k8s'

// 主机相关类型
export interface Host {
  host_id: string
  hostname: string
  os_family: string
  os_version: string
  kernel_version: string
  arch: string
  ipv4: string[]
  status: 'online' | 'offline'
  last_heartbeat: string
  created_at: string
  updated_at: string
  baseline_score?: number
  baseline_pass_rate?: number
  tags?: string[]
  // 运行时环境
  runtime_type?: RuntimeType // 运行时类型：vm/docker/k8s
  is_container?: boolean // 是否为容器环境
  container_id?: string // 容器ID
  // K8s 相关字段
  pod_name?: string // Pod 名称（K8s 环境）
  pod_namespace?: string // 命名空间（K8s 环境）
  pod_uid?: string // Pod UID（K8s 环境）
  business_line?: string // 业务线
  agent_version?: string // Agent 当前版本号
  // 时间信息
  agent_start_time?: string // Agent 启动时间
  system_boot_time?: string // 系统启动时间
  last_active_time?: string // 最近活跃时间
}

// 磁盘信息类型（用于 Host 的 disk_info 字段）
export interface DiskInfo {
  device: string // /dev/sda1
  mount_point: string // /、/home 等
  file_system: string // ext4、xfs 等
  total_size: number // 总大小（字节）
  used_size: number // 已用大小（字节）
  available_size: number // 可用大小（字节）
  usage_percent: number // 使用率（百分比）
}

// 网卡信息类型（用于 Host 的 network_interfaces 字段）
export interface NetworkInterfaceInfo {
  interface_name: string // eth0、ens33 等
  mac_address?: string
  ipv4_addresses?: string[]
  ipv6_addresses?: string[]
  mtu?: number
  state?: string // up、down
}

export interface HostDetail extends Host {
  baseline_results: ScanResult[]
  device_model?: string
  manufacturer?: string
  system_load?: string
  cpu_info?: string
  memory_size?: string
  default_gateway?: string
  network_mode?: string
  cpu_usage?: string
  memory_usage?: string
  dns_servers?: string[]
  device_serial?: string
  device_id?: string
  public_ipv4?: string[]
  public_ipv6?: string[]
  ipv6?: string[] // IPv6 地址列表
  business_line?: string
  system_boot_time?: string
  agent_start_time?: string
  last_active_time?: string
  tags?: string[]
  disk_info?: string // JSON 字符串，解析后为 DiskInfo[]
  network_interfaces?: string // JSON 字符串，解析后为 NetworkInterfaceInfo[]
}

// 策略组相关类型
export interface PolicyGroup {
  id: string
  name: string
  description: string
  icon?: string
  color?: string
  sort_order: number
  enabled: boolean
  created_at: string
  updated_at: string
  policies?: Policy[]
  // 统计数据
  policy_count?: number
  rule_count?: number
  pass_rate?: number
  host_count?: number
}

export interface PolicyGroupStatistics {
  group_id: string
  policy_count: number
  rule_count: number
  host_count: number
  pass_rate: number
  pass_count: number
  fail_count: number
  risk_count: number
  last_check_time?: string
}

// OS 版本要求类型
export interface OSRequirement {
  os_family: string   // rocky, centos, debian 等
  min_version?: string // 最小版本（含）
  max_version?: string // 最大版本（含）
}

// 策略相关类型
export interface Policy {
  id: string
  name: string
  version: string
  description: string
  os_family: string[]
  os_version: string
  os_requirements?: OSRequirement[] // 详细 OS 版本要求
  target_type?: 'host' | 'container' | 'all' // 废弃，保留向后兼容
  runtime_types?: RuntimeType[] // 适用的运行时类型：["vm", "docker", "k8s"]，空表示全部
  enabled: boolean
  group_id?: string // 所属策略组ID
  rule_count?: number
  rules?: Rule[]
  created_at: string
  updated_at: string
}

export interface Rule {
  rule_id: string
  policy_id: string
  category: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  enabled: boolean
  target_type?: 'host' | 'container' | 'all' // 废弃，保留向后兼容
  runtime_types?: RuntimeType[] // 适用的运行时类型：["vm", "docker", "k8s"]，空表示全部
  check_config: CheckConfig
  fix_config: FixConfig
  created_at: string
  updated_at: string
}

export interface CheckConfig {
  condition?: 'all' | 'any'
  rules?: CheckRule[]
  type?: string
  [key: string]: any
}

export interface CheckRule {
  type: string
  param: string[]
  result?: string
}

export interface FixConfig {
  suggestion?: string
  command?: string
  [key: string]: any
}

// 任务相关类型
export interface ScanTask {
  task_id: string
  name: string
  type: 'manual' | 'scheduled' | 'baseline'
  target_type: 'all' | 'host_ids' | 'os_family'
  target_config: {
    host_ids?: string[]
    os_family?: string[]
  }
  target_hosts?: string[] // 目标主机 ID 列表
  matched_host_count?: number // 匹配的主机数量（在线）
  total_host_count?: number // 总目标主机数量（包括离线）
  total_rule_count?: number // 关联策略的规则总数
  expected_check_count?: number // 预期检查项总数（在线主机数 × 规则数）
  policy_id: string // 兼容旧数据：单策略
  policy_ids?: string[] // 新字段：多策略
  rule_ids?: string[]
  status: 'created' | 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  created_at: string
  executed_at?: string
  completed_at?: string
  updated_at: string
}

// 检测结果相关类型
export interface ScanResult {
  task_id: string
  host_id: string
  rule_id: string
  policy_id: string
  category: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'pass' | 'fail' | 'error' | 'na'
  actual?: string
  expected?: string
  fix_suggestion?: string
  checked_at: string
}

export interface BaselineScore {
  host_id: string
  baseline_score: number
  pass_rate: number
  total_rules: number
  pass_count: number
  fail_count: number
  error_count: number
  na_count: number
  calculated_at: string
}

export interface BaselineSummary {
  host_id: string
  by_severity: {
    critical: { pass: number; fail: number; error: number; na: number }
    high: { pass: number; fail: number; error: number; na: number }
    medium: { pass: number; fail: number; error: number; na: number }
    low: { pass: number; fail: number; error: number; na: number }
  }
  by_category: Record<string, { pass: number; fail: number; error: number; na: number }>
}

// 资产数据相关类型
export interface Process {
  id: string
  host_id: string
  pid: string
  ppid: string
  cmdline: string
  exe: string
  exe_hash?: string
  container_id?: string
  uid: string
  gid: string
  username?: string
  groupname?: string
  collected_at: string
}

export interface Port {
  id: string
  host_id: string
  protocol: string // tcp/udp
  port: number
  state?: string // LISTEN/ESTABLISHED 等
  pid?: string
  process_name?: string
  container_id?: string
  collected_at: string
}

export interface AssetUser {
  id: string
  host_id: string
  username: string
  uid: string
  gid: string
  groupname?: string
  home_dir: string
  shell: string
  comment?: string
  has_password: boolean
  collected_at: string
}

export interface Software {
  id: string
  host_id: string
  name: string
  version?: string
  architecture?: string
  package_type: string // rpm、deb、pip、npm、jar 等
  vendor?: string
  install_time?: string
  collected_at: string
}

export interface Container {
  id: string
  host_id: string
  container_id: string
  container_name?: string
  image?: string
  image_id?: string
  runtime?: string // docker、containerd
  status?: string // running、stopped 等
  created_at?: string
  collected_at: string
}

export interface App {
  id: string
  host_id: string
  app_type: string // mysql、redis、nginx、kafka 等
  app_name?: string
  version?: string
  port?: number
  process_id?: string
  config_path?: string
  data_path?: string
  collected_at: string
}

export interface NetInterface {
  id: string
  host_id: string
  interface_name: string // eth0、ens33 等
  mac_address?: string
  ipv4_addresses?: string[]
  ipv6_addresses?: string[]
  mtu?: number
  state?: string // up、down
  collected_at: string
}

export interface Volume {
  id: string
  host_id: string
  device?: string // /dev/sda1
  mount_point?: string // /、/home 等
  file_system?: string // ext4、xfs 等
  total_size?: number // 总大小（字节）
  used_size?: number // 已用大小（字节）
  available_size?: number // 可用大小（字节）
  usage_percent?: number // 使用率（百分比）
  collected_at: string
}

export interface Kmod {
  id: string
  host_id: string
  module_name: string
  size?: number // 模块大小（字节）
  used_by?: number // 引用计数
  state?: string // Live、Loading、Unloading
  collected_at: string
}

export interface Service {
  id: string
  host_id: string
  service_name: string
  service_type?: string // systemd、sysv
  status?: string // active、inactive、failed 等
  enabled?: boolean // 是否开机自启
  description?: string
  collected_at: string
}

export interface Cron {
  id: string
  host_id: string
  user: string // root、username
  schedule: string // 调度表达式（* * * * *）
  command: string // 执行的命令
  cron_type?: string // crontab、systemd-timer
  enabled?: boolean // 是否启用
  collected_at: string
}

// 主机监控数据相关类型
export interface HostMetrics {
  host_id: string
  latest?: LatestMetrics
  time_series?: TimeSeriesMetrics
  source: 'prometheus'
}

export interface LatestMetrics {
  cpu_usage?: number
  mem_usage?: number
  disk_usage?: number
  net_bytes_sent?: number
  net_bytes_recv?: number
  disk_read_bytes?: number
  disk_write_bytes?: number
  agent_cpu_usage?: number
  agent_mem_rss?: number
  agent_mem_percent?: number
  collected_at?: string
}

export interface TimeSeriesMetrics {
  cpu_usage?: TimeSeriesPoint[]
  mem_usage?: TimeSeriesPoint[]
  disk_usage?: TimeSeriesPoint[]
  net_in?: TimeSeriesPoint[]
  net_out?: TimeSeriesPoint[]
  disk_read?: TimeSeriesPoint[]
  disk_write?: TimeSeriesPoint[]
  agent_cpu?: TimeSeriesPoint[]
  agent_mem?: TimeSeriesPoint[]
}

export interface TimeSeriesPoint {
  timestamp: string
  value: number
}

// 策略统计信息相关类型
export interface PolicyStatistics {
  policy_id: string
  rule_count: number
  host_count: number
  pass_rate: number
  pass_count: number
  fail_count: number
  risk_count: number
  last_check_time?: string
  by_severity?: {
    critical: { pass: number; fail: number }
    high: { pass: number; fail: number }
    medium: { pass: number; fail: number }
    low: { pass: number; fail: number }
  }
}

// 基线修复相关类型
export interface FixTask {
  task_id: string
  host_ids: string[]
  rule_ids: string[]
  severities?: string[]
  status: 'pending' | 'running' | 'completed' | 'failed'
  total_count: number
  success_count: number
  failed_count: number
  progress: number
  created_by: string
  created_at: string
  completed_at?: string
}

export interface FixResult {
  task_id: string
  host_id: string
  hostname?: string
  rule_id: string
  title: string
  status: 'success' | 'failed' | 'skipped'
  message?: string
  command?: string
  output?: string
  error_msg?: string
  fixed_at: string
}

export interface FixTaskHostStatus {
  id: number
  task_id: string
  host_id: string
  hostname: string
  ip_address: string
  business_line: string
  os_family: string
  os_version: string
  runtime_type: string
  status: 'dispatched' | 'completed' | 'timeout' | 'failed'
  dispatched_at: string
  completed_at?: string
  error_message?: string
  created_at: string
  updated_at: string
}

// FIM（文件完整性监控）相关类型
export interface FIMWatchPath {
  path: string
  level: string // NORMAL, CONTENT, PERMS
  comment: string
}

export interface FIMPolicy {
  policy_id: string
  name: string
  description: string
  watch_paths: FIMWatchPath[]
  exclude_paths: string[]
  check_interval_hours: number
  target_type: string // all/host_ids/business_line
  target_config: {
    host_ids?: string[]
    os_family?: string[]
  }
  escalation_timeout_min: number
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface FIMChangeDetail {
  size_before?: string
  size_after?: string
  hash_before?: string
  hash_after?: string
  mode_before?: string
  mode_after?: string
  hash_changed: boolean
  permission_changed: boolean
  owner_changed: boolean
  attributes?: string
}

export interface FIMEvent {
  event_id: string
  host_id: string
  hostname: string
  task_id: string
  file_path: string
  change_type: 'added' | 'removed' | 'changed'
  change_detail: FIMChangeDetail
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string // binary/config/auth/log/other
  status: 'pending' | 'confirmed' | 'escalated'
  confirmed_by?: string
  confirmed_at?: string
  confirm_reason?: string
  alert_id?: number
  detected_at: string
  created_at: string
}

export interface FIMTask {
  task_id: string
  policy_id: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  target_type: string
  target_config: {
    host_ids?: string[]
    os_family?: string[]
  }
  dispatched_host_count: number
  completed_host_count: number
  total_events: number
  created_at: string
  executed_at?: string
  completed_at?: string
}

export interface FIMTaskHostStatus {
  id: number
  task_id: string
  host_id: string
  hostname: string
  status: 'dispatched' | 'completed' | 'timeout' | 'failed'
  total_entries: number
  added_count: number
  removed_count: number
  changed_count: number
  run_time_sec: number
  error_message?: string
  dispatched_at?: string
  completed_at?: string
}

export interface FIMHostEventCount {
  host_id: string
  hostname: string
  count: number
}

export interface FIMEventTrendPoint {
  date: string
  count: number
}

export interface FIMEventStats {
  total: number
  pending: number
  critical: number
  high: number
  medium: number
  low: number
  added: number
  removed: number
  changed: number
  by_category: Record<string, number>
  top_hosts: FIMHostEventCount[]
  trend: FIMEventTrendPoint[]
}

export interface FIMBaseline {
  id: number
  policy_id: string
  host_id: string
  hostname: string
  version: number
  status: 'pending' | 'approved' | 'outdated'
  entry_count: number
  approved_by?: string
  approved_at?: string
  task_id: string
  created_at: string
  updated_at: string
}

export interface FIMBaselineEntry {
  id: number
  baseline_id: number
  file_path: string
  sha256: string
  file_size: number
  file_mode: string
  uid: number
  gid: number
  mtime: number
}

export interface FixableItem {
  task_id: string
  host_id: string
  hostname: string
  ip: string
  business_line?: string
  rule_id: string
  title: string
  category: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  fix_suggestion?: string
  fix_command?: string
  actual?: string
  expected?: string
  has_fix: boolean
}
