import { get, post, put, del } from "./client";
import type {
  Component, ComponentDetail, ComponentVersion, PluginSyncStatus, ComponentPushRecord,
  InspectionOverview, Backup, BackupConfig, MigrationJob, MigrationTestResult,
  ReportStats, TaskReportMap, TaskReportType, Paged,
} from "./types";

export interface MigrationConnInput { source_url: string; source_user: string; password: string }
export interface MigrationStartInput extends MigrationConnInput { scope: string[] }

export const operationsApi = {
  // ---- 组件管理 ----
  // /components 返回裸数组
  listComponents: (params?: { category?: string }) => get<Component[]>("/components", params),
  getComponent: (id: number) => get<ComponentDetail>(`/components/${id}/versions`),
  createComponent: (body: Partial<Component>) => post<Component>("/components", body),
  deleteComponent: (id: number) => del<void>(`/components/${id}`),
  listVersions: (id: number) => get<ComponentDetail>(`/components/${id}/versions`),
  createVersion: (id: number, body: { version: string; changelog?: string }) =>
    post<ComponentVersion>(`/components/${id}/versions`, body),
  setLatest: (id: number, versionId: number) =>
    put<void>(`/components/${id}/versions/${versionId}/set-latest`),
  deleteVersion: (id: number, versionId: number) =>
    del<void>(`/components/${id}/versions/${versionId}`),
  // 文件上传：仅声明签名，调用方传 FormData（content-type 由 axios 自动处理）
  uploadPackage: (id: number, versionId: number, form: FormData) =>
    post<void>(`/components/${id}/versions/${versionId}/packages`, form),
  deletePackage: (packageId: number) => del<void>(`/packages/${packageId}`),
  pluginStatus: () => get<PluginSyncStatus[]>("/components/plugin-status"),
  pushAgentUpdate: (body: object) => post<void>("/components/agent/push-update", body),
  // /components/push-records 返回 Paged
  listPushRecords: (params?: { page?: number; page_size?: number }) =>
    get<Paged<ComponentPushRecord>>("/components/push-records", params),
  broadcastPlugins: (body?: object) => post<void>("/components/plugins/broadcast", body),

  // ---- 运维巡检 ----
  inspectionOverview: () => get<InspectionOverview>("/inspection/overview"),
  restartAgent: (hostId: string) => post<void>(`/inspection/hosts/${hostId}/restart-agent`),
  batchRestartAgent: (body: { host_ids: string[] }) =>
    post<void>("/inspection/batch-restart-agent", body),

  // ---- 配置备份（实际路径 /system/backups 复数、/system/backup-config）----
  listBackups: (params?: { page?: number; page_size?: number }) =>
    get<Paged<Backup>>("/system/backups", params),
  createBackup: (body: { scope: string; remark?: string }) => post<Backup>("/system/backups", body),
  restoreBackup: (id: number) => post<void>(`/system/backups/${id}/restore`),
  deleteBackup: (id: number) => del<void>(`/system/backups/${id}`),
  getBackupConfig: () => get<BackupConfig>("/system/backup-config"),
  updateBackupConfig: (body: BackupConfig) => put<void>("/system/backup-config", body),

  // ---- 迁移助手 ----
  testConnection: (body: MigrationConnInput) =>
    post<MigrationTestResult>("/system/migration/test-connection", body),
  listMigrationJobs: (params?: { page?: number; page_size?: number }) =>
    get<Paged<MigrationJob>>("/system/migration/jobs", params),
  startMigrationJob: (body: MigrationStartInput) => post<MigrationJob>("/system/migration/jobs", body),
  getMigrationJob: (id: number) => get<MigrationJob>(`/system/migration/jobs/${id}`),
  cancelMigrationJob: (id: number) => post<void>(`/system/migration/jobs/${id}/cancel`),

  // ---- 报告管理 ----
  reportStats: (params?: { start_date?: string; end_date?: string }) =>
    get<ReportStats>("/reports/stats", params),

  // ---- 任务报告（后端无 /task-reports；按报告类型走 /reports/{type}，返回聚合对象）----
  taskReport: <T extends TaskReportType>(type: T) => get<TaskReportMap[T]>(`/reports/${type}`),
};
