import { get, post, del } from "./client";
import type {
  Paged,
  VirusScanTask,
  VirusScanResult,
  VirusStatistics,
  QuarantineItem,
  QuarantineStatistics,
} from "./types";

export interface VirusTaskParams {
  page: number;
  page_size: number;
  keyword?: string;
  status?: string;
  scan_type?: string;
}

export interface VirusResultParams {
  page: number;
  page_size: number;
  keyword?: string;
  severity?: string;
  threat_type?: string;
  action?: string;
  task_id?: number;
}

export interface VirusScanCreate {
  name: string;
  scanType: string;
  scanPaths?: string[];
  hostIds: string[];
}

export interface QuarantineParams {
  page: number;
  page_size: number;
  keyword?: string;
  status?: string;
  severity?: string;
  threat_type?: string;
  host_id?: string;
}

export const virusApi = {
  // 扫描任务
  listTasks: (params: VirusTaskParams) => get<Paged<VirusScanTask>>("/antivirus/tasks", params),
  getTask: (id: number) => get<VirusScanTask>(`/antivirus/tasks/${id}`),
  createTask: (body: VirusScanCreate) => post<VirusScanTask>("/antivirus/tasks", body),
  cancelTask: (id: number) => post<void>(`/antivirus/tasks/${id}/cancel`),
  deleteTask: (id: number) => del<void>(`/antivirus/tasks/${id}`),

  // 扫描结果（恶意文件检测）
  listResults: (params: VirusResultParams) => get<Paged<VirusScanResult>>("/antivirus/results", params),
  getResult: (id: number) => get<VirusScanResult>(`/antivirus/results/${id}`),
  quarantineResult: (id: number) => post<void>(`/antivirus/results/${id}/quarantine`),
  ignoreResult: (id: number) => post<void>(`/antivirus/results/${id}/ignore`),
  deleteFileResult: (id: number) => post<void>(`/antivirus/results/${id}/delete-file`),

  // 统计
  statistics: () => get<VirusStatistics>("/antivirus/statistics"),

  // 文件隔离箱
  listQuarantine: (params: QuarantineParams) => get<Paged<QuarantineItem>>("/quarantine/files", params),
  getQuarantine: (id: number) => get<QuarantineItem>(`/quarantine/files/${id}`),
  restoreQuarantine: (id: number) => post<void>(`/quarantine/files/${id}/restore`),
  deleteQuarantine: (id: number) => del<void>(`/quarantine/files/${id}`),
  quarantineStatistics: () => get<QuarantineStatistics>("/quarantine/statistics"),
};
