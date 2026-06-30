import { get, post, put, del } from "./client";
import type {
  Paged,
  EdrEvent,
  EdrEventStats,
  DetectionRule,
  DetectionRuleStats,
  ThreatIntelStats,
  ThreatIntelIocList,
  ThreatIntelCheckResult,
  IntelSyncSchedule,
  IntelSyncExecution,
  Storyline,
  StorylineDetail,
  StorylineStats,
  HuntingQuery,
  HuntingResult,
  AnomalyEvent,
  AnomalyStats,
  BdeBaseline,
  BdeBaselineStats,
  BdeAlert,
} from "./types";

// 端点镜像 ui/src/api（edr/detection-rules/threat-intel/storyline/hunting/anomaly/bde），全部 /api/v1。
export const detectionApi = {
  // EDR 事件
  listEdrEvents: (params: {
    page: number;
    page_size: number;
    host_id?: string;
    hostname?: string;
    event_type?: string;
    data_type?: number;
    exe?: string;
    cmdline?: string;
    file_path?: string;
    remote_addr?: string;
    pid?: string;
    keyword?: string;
    date_from?: string;
    date_to?: string;
  }) => get<Paged<EdrEvent>>("/edr/events", params),
  edrEventStats: (hours?: number) => get<EdrEventStats>("/edr/events/stats", { hours }),

  // 检测规则
  listRules: (params: { page: number; page_size: number; keyword?: string; severity?: string; category?: string; enabled?: string }) =>
    get<{ total: number; items: DetectionRule[] }>("/detection-rules", params),
  getRule: (id: number) => get<DetectionRule>(`/detection-rules/${id}`),
  createRule: (body: Partial<DetectionRule>) => post<DetectionRule>("/detection-rules", body),
  updateRule: (id: number, body: Partial<DetectionRule>) => put<DetectionRule>(`/detection-rules/${id}`, body),
  deleteRule: (id: number) => del<void>(`/detection-rules/${id}`),
  toggleRule: (id: number) => post<void>(`/detection-rules/${id}/toggle`),
  ruleCategories: () => get<string[]>("/detection-rules/categories"),
  ruleMitreIds: () => get<string[]>("/detection-rules/mitre-ids"),
  ruleStats: () => get<DetectionRuleStats>("/detection-rules/statistics"),

  // 威胁情报
  threatIntelStats: () => get<ThreatIntelStats>("/threat-intel/stats"),
  listIocs: (params: { type?: string; page: number; page_size: number }) => get<ThreatIntelIocList>("/threat-intel/iocs", params),
  checkIoc: (type: string, value: string) => post<ThreatIntelCheckResult>("/threat-intel/check", { type, value }),
  syncThreatIntel: () => post<{ message: string }>("/threat-intel/sync"),
  threatIntelSyncStatus: () => get<{ status: string; message: string }>("/threat-intel/sync-status"),

  // 威胁情报同步计划
  listIntelSchedules: () => get<IntelSyncSchedule[]>("/threat-intel/schedules"),
  createIntelSchedule: (body: { name: string; cronExpr: string }) =>
    post<void>("/threat-intel/schedules", body),
  updateIntelSchedule: (id: number, body: Partial<IntelSyncSchedule>) =>
    put<void>(`/threat-intel/schedules/${id}`, body),
  deleteIntelSchedule: (id: number) => del<void>(`/threat-intel/schedules/${id}`),
  toggleIntelSchedule: (id: number) => post<void>(`/threat-intel/schedules/${id}/toggle`),
  runIntelSchedule: (id: number) => post<void>(`/threat-intel/schedules/${id}/run`),
  listIntelExecutions: (id: number, params: { page: number; pageSize: number }) =>
    get<{ items: IntelSyncExecution[]; total: number; page: number }>(`/threat-intel/schedules/${id}/executions`, params),

  // 攻击故事线
  listStorylines: (params: { page: number; page_size: number; host_id?: string; severity?: string; status?: string }) =>
    get<Paged<Storyline>>("/storylines", params),
  getStoryline: (storyId: string, params?: { page?: number; page_size?: number }) => get<StorylineDetail>(`/storylines/${storyId}`, params),
  resolveStoryline: (storyId: string) => post<void>(`/storylines/${storyId}/resolve`),
  storylineStats: () => get<StorylineStats>("/storylines/stats"),

  // 威胁狩猎
  executeHunt: (mql: string, timeout_seconds?: number) => post<HuntingResult>("/hunting/query", { mql, timeout_seconds }),
  listHuntQueries: (params: { page: number; page_size: number; category?: string }) => get<Paged<HuntingQuery>>("/hunting/queries", params),
  createHuntQuery: (body: { name: string; description?: string; mql: string; category?: string; severity?: string }) =>
    post<HuntingQuery>("/hunting/queries", body),
  deleteHuntQuery: (id: number) => del<void>(`/hunting/queries/${id}`),

  // ML 异常检测
  listAnomalies: (params: { page: number; page_size: number; host_id?: string; alert_type?: string; severity?: string; status?: string }) =>
    get<Paged<AnomalyEvent>>("/anomalies", params),
  anomalyStats: () => get<AnomalyStats>("/anomalies/stats"),
  resolveAnomaly: (id: number, status: "confirmed" | "false_positive") => put<void>(`/anomalies/${id}/resolve`, { status }),

  // 行为基线（BDE）
  listBdeStates: (params: { page: number; page_size: number; phase?: string; host_id?: string }) =>
    get<Paged<BdeBaseline>>("/bde/baseline/states", params),
  bdeStats: () => get<BdeBaselineStats>("/bde/baseline/stats"),
  listBdeAlerts: (params: { page: number; page_size: number; host_id?: string; status?: string; metric?: string }) =>
    get<Paged<BdeAlert>>("/bde/alerts", params),
};
