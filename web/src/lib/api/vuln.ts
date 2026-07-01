import { get, post, put, del } from "./client";
import type {
  Paged,
  Vulnerability,
  VulnerabilityListResult,
  VulnBulletin,
  VulnBulletinStatistics,
  VulnScanSchedule,
  RemediationReport,
  RemediationTrendItem,
  RemediationTask,
  RemediationTaskStats,
  RemediationPolicy,
  RemediationPolicyPreview,
  VulnDbStats,
  VulnDbImport,
  VulnDataSource,
  VulnDataSourceTestResult,
  SbomProject,
} from "./types";

// 端点全部镜像现有 Vue（ui/src/api）。后端字段 camelCase。
export const vulnApi = {
  // ---- 漏洞列表 ----
  // GET /vulnerabilities → { items, total, stats }
  listVulns: (params: {
    page: number;
    page_size: number;
    search?: string;
    severity?: string;
    status?: string;
    component?: string;
    host_id?: string;
    asset_type?: string;
    fix_owner?: string;
    show_all?: boolean;
    sort?: string;
  }) => get<VulnerabilityListResult>("/vulnerabilities", params),
  getVuln: (id: number) => get<Vulnerability>(`/vulnerabilities/${id}`),
  ignoreVuln: (id: number) => post<void>(`/vulnerabilities/${id}/ignore`),
  unignoreVuln: (id: number) => post<void>(`/vulnerabilities/${id}/unignore`),
  triggerScan: (body: { scope?: string; host_ids?: string[]; business_line?: string; sync_db?: boolean }) =>
    post<{ task_id: string }>("/vulnerabilities/scan", body),

  // ---- 漏洞通报 ----
  // GET /vuln-bulletins → Paged
  listBulletins: (params: {
    page: number;
    page_size: number;
    priority?: string;
    status?: string;
    cve_id?: string;
    component?: string;
    search?: string;
    sla_breached?: string;
    sort?: string;
  }) => get<Paged<VulnBulletin>>("/vuln-bulletins", params),
  getBulletin: (id: number) =>
    get<{ bulletin: VulnBulletin; affected_hosts: unknown[] }>(`/vuln-bulletins/${id}`),
  bulletinStatistics: () => get<VulnBulletinStatistics>("/vuln-bulletins/statistics"),
  ackBulletin: (id: number) => put<void>(`/vuln-bulletins/${id}/acknowledge`),
  resolveBulletin: (id: number, comment?: string) => put<void>(`/vuln-bulletins/${id}/resolve`, { comment }),
  ignoreBulletin: (id: number, reason?: string) => put<void>(`/vuln-bulletins/${id}/ignore`, { reason }),
  reopenBulletin: (id: number) => put<void>(`/vuln-bulletins/${id}/reopen`),

  // ---- 扫描计划（裸数组）----
  listScanSchedules: () => get<VulnScanSchedule[]>("/vulnerabilities/schedules"),
  createScanSchedule: (body: { name: string; scanType: string; cronExpr: string }) =>
    post<VulnScanSchedule>("/vulnerabilities/schedules", body),
  updateScanSchedule: (id: number, body: Partial<VulnScanSchedule>) =>
    put<VulnScanSchedule>(`/vulnerabilities/schedules/${id}`, body),
  deleteScanSchedule: (id: number) => del<void>(`/vulnerabilities/schedules/${id}`),
  toggleScanSchedule: (id: number) => post<void>(`/vulnerabilities/schedules/${id}/toggle`),

  // ---- 修复报告（统计聚合）----
  remediationReport: () => get<RemediationReport>("/vulnerabilities/stats/remediation"),
  remediationTrend: (days = 30) => get<RemediationTrendItem[]>("/vulnerabilities/stats/trend", { days }),

  // ---- 修复任务 ----
  listRemediationTasks: (params: {
    page: number;
    page_size: number;
    status?: string;
    vuln_id?: string;
    host_id?: string;
  }) => get<Paged<RemediationTask>>("/remediation-tasks", params),
  getRemediationTask: (id: number) => get<RemediationTask>(`/remediation-tasks/${id}`),
  remediationTaskStats: () => get<RemediationTaskStats>("/remediation-tasks/stats"),
  createRemediationTask: (body: { vulnId: number; hostIds: string[] }) =>
    post<{ created: number; tasks: RemediationTask[] }>("/remediation-tasks", body),
  confirmRemediationTask: (id: number, command?: string) =>
    post<void>(`/remediation-tasks/${id}/confirm`, command ? { command } : {}),
  cancelRemediationTask: (id: number) => post<void>(`/remediation-tasks/${id}/cancel`),
  retryRemediationTask: (id: number, command?: string) =>
    post<void>(`/remediation-tasks/${id}/retry`, command ? { command } : {}),

  // ---- 修复策略（裸数组 + CRUD）----
  listRemediationPolicies: () => get<RemediationPolicy[]>("/remediation-policies"),
  getRemediationPolicy: (id: number) => get<RemediationPolicy>(`/remediation-policies/${id}`),
  createRemediationPolicy: (body: Partial<RemediationPolicy>) =>
    post<RemediationPolicy>("/remediation-policies", body),
  updateRemediationPolicy: (id: number, body: Partial<RemediationPolicy>) =>
    put<RemediationPolicy>(`/remediation-policies/${id}`, body),
  deleteRemediationPolicy: (id: number) => del<void>(`/remediation-policies/${id}`),
  executeRemediationPolicy: (id: number) => post<void>(`/remediation-policies/${id}/execute`),
  previewRemediationPolicy: (id: number) =>
    post<RemediationPolicyPreview>(`/remediation-policies/${id}/preview`),

  // ---- 漏洞库管理（cache）----
  vulnDbStats: () => get<VulnDbStats>("/vulnerabilities/cache/stats"),
  listVulnDbImports: () => get<Paged<VulnDbImport>>("/vulnerabilities/cache/imports"),
  purgeVulnDb: () => post<void>("/vulnerabilities/cache/purge"),
  // 导入为 multipart/form-data，地基阶段先留 stub（真实页实现）
  importVulnDb: (_form: FormData): Promise<{ importedCount: number }> => {
    throw new Error("not implemented: importVulnDb (multipart upload)");
  },

  // ---- 漏洞源管理（裸数组）----
  listDataSources: () => get<VulnDataSource[]>("/vuln-data-sources"),
  updateDataSource: (id: number, body: { enabled?: boolean; baseUrl?: string }) =>
    put<VulnDataSource>(`/vuln-data-sources/${id}`, body),
  testDataSource: (id: number) => post<VulnDataSourceTestResult>(`/vuln-data-sources/${id}/test`),
  syncDataSource: (id: number) => post<void>(`/vuln-data-sources/${id}/sync`),

  // ---- SBOM 导入（GET → array | null）----
  listSbomProjects: () => get<SbomProject[] | null>("/sbom/projects"),
  getSbomProject: (name: string) => get<unknown>(`/sbom/projects/${name}`),
  // 导入为 multipart/form-data，地基阶段先留 stub
  importSbom: (_form: FormData): Promise<unknown> => {
    throw new Error("not implemented: importSbom (multipart upload)");
  },
};
