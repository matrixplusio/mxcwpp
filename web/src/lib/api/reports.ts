import { get, del, getBlob } from "./client";
import type {
  ReportStats,
  BaselineScoreTrend,
  CheckResultTrend,
  TopFailedRule,
  TopRiskHost,
  AntivirusModuleReport,
  VulnModuleReport,
  KubeModuleReport,
  EdrModuleReport,
  ExecutiveTaskReport,
  AntivirusExecutiveReport,
  VulnExecutiveReport,
  KubeExecutiveReport,
  RemediationExecutiveReport,
  EdrExecutiveReport,
  GeneratedReportList,
  BaselineTask,
  VirusScanTask,
  Paged,
} from "./types";

export interface DateRange { start: string; end: string; }

export interface TrendParams {
  start_time?: string;
  end_time?: string;
  host_id?: string;
  policy_id?: string;
  interval?: "hour" | "day" | "week" | "month";
}

function rangeParams(range?: DateRange) {
  return range ? { start_time: range.start, end_time: range.end } : undefined;
}

export const reportsApi = {
  // --- Module reports ---
  stats: (range?: DateRange) =>
    get<ReportStats>("/reports/stats", rangeParams(range)),

  baselineScoreTrend: (params?: TrendParams) =>
    get<BaselineScoreTrend>("/reports/baseline-score-trend", params),

  checkResultTrend: (params?: TrendParams) =>
    get<CheckResultTrend>("/reports/check-result-trend", params),

  topFailedRules: (limit?: number) =>
    get<TopFailedRule[]>("/reports/top-failed-rules", limit !== undefined ? { limit } : undefined),

  topRiskHosts: (limit?: number) =>
    get<TopRiskHost[]>("/reports/top-risk-hosts", limit !== undefined ? { limit } : undefined),

  antivirusModule: (range?: DateRange) =>
    get<AntivirusModuleReport>("/reports/antivirus", rangeParams(range)),

  vulnModule: (range?: DateRange) =>
    get<VulnModuleReport>("/reports/vulnerability", rangeParams(range)),

  kubeModule: (range?: DateRange) =>
    get<KubeModuleReport>("/reports/kube", rangeParams(range)),

  edrModule: (range?: DateRange) =>
    get<EdrModuleReport>("/reports/edr", rangeParams(range)),

  // --- Baseline task detail ---
  taskDetail: (taskId: string) =>
    get<Record<string, unknown>>(`/reports/task/${taskId}`),

  taskExecutive: (taskId: string) =>
    get<ExecutiveTaskReport>(`/reports/task/${taskId}/executive`),

  taskHostDetail: (taskId: string, hostId: string) =>
    get<Record<string, unknown>>(`/reports/task/${taskId}/host/${hostId}`),

  // --- Executive reports ---
  antivirusExecutive: (taskId: string | number) =>
    get<AntivirusExecutiveReport>(`/reports/antivirus/${taskId}/executive`),

  vulnExecutive: (range?: DateRange) =>
    get<VulnExecutiveReport>("/reports/vulnerability/executive", rangeParams(range)),

  kubeExecutive: (range?: DateRange) =>
    get<KubeExecutiveReport>("/reports/kube/executive", rangeParams(range)),

  remediationExecutive: (range?: DateRange) =>
    get<RemediationExecutiveReport>("/reports/remediation/executive", rangeParams(range)),

  edrExecutive: (range?: DateRange) =>
    get<EdrExecutiveReport>("/reports/edr/executive", rangeParams(range)),

  // --- Saved reports ---
  listGenerated: (type?: string) =>
    get<GeneratedReportList>("/reports/generated", type ? { report_type: type } : undefined),

  getGenerated: (id: number) =>
    get<Record<string, unknown>>(`/reports/generated/${id}`),

  deleteGenerated: (id: number) =>
    del<null>(`/reports/generated/${id}`),

  // --- PDF blob download ---
  downloadPdf: async (
    path: string,
    params?: Record<string, string | number | boolean>,
    filename?: string,
  ): Promise<void> => {
    const blob = await getBlob(path, params);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename ?? path.split("/").filter(Boolean).pop() ?? "report.pdf";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  // --- Task selectors (for report page dropdowns) ---
  completedBaselineTasks: () =>
    get<Paged<BaselineTask>>("/tasks", { status: "completed", page_size: 100 }),

  antivirusTasks: () =>
    get<Paged<VirusScanTask>>("/antivirus/tasks"),
};
