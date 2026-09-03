import { get, post, put, del } from "./client";
import type {
  Paged,
  FimPolicy,
  FimEvent,
  FimEventDetail,
  FimEventStats,
  FimTask,
  FimTaskHostStatus,
  FimBaseline,
  FimBaselineEntry,
} from "./types";

export const fimApi = {
  // === 策略管理 ===
  listPolicies: (params: { page: number; page_size: number; name?: string; enabled?: string }) =>
    get<Paged<FimPolicy>>("/fim/policies", params),
  getPolicy: (policyId: string) => get<FimPolicy>(`/fim/policies/${policyId}`),
  createPolicy: (body: Partial<FimPolicy>) => post<FimPolicy>("/fim/policies", body),
  updatePolicy: (policyId: string, body: Partial<FimPolicy>) => put<FimPolicy>(`/fim/policies/${policyId}`, body),
  deletePolicy: (policyId: string) => del<void>(`/fim/policies/${policyId}`),

  // === 任务管理 ===
  listTasks: (params: { page: number; page_size: number; policy_id?: string; status?: string }) =>
    get<Paged<FimTask>>("/fim/tasks", params),
  getTask: (taskId: string) =>
    get<{ task: FimTask; host_statuses: FimTaskHostStatus[] }>(`/fim/tasks/${taskId}`),
  createTask: (body: { policy_id: string; target_type?: string; target_config?: object }) =>
    post<FimTask>("/fim/tasks", body),
  runTask: (taskId: string) => post<FimTask>(`/fim/tasks/${taskId}/run`),

  // === 事件查询 ===
  listEvents: (params: {
    page: number;
    page_size: number;
    host_id?: string;
    hostname?: string;
    file_path?: string;
    change_type?: string;
    severity?: string;
    category?: string;
    status?: string;
    task_id?: string;
    date_from?: string;
    date_to?: string;
  }) => get<Paged<FimEvent>>("/fim/events", params),
  getEvent: (eventId: string) => get<FimEventDetail>(`/fim/events/${eventId}`),
  getEventStats: (days?: number) => get<FimEventStats>("/fim/events/stats", { days }),
  confirmEvent: (eventId: string, body: { reason: string; update_baseline?: boolean }) =>
    post<void>(`/fim/events/${eventId}/confirm`, body),
  batchConfirmEvents: (event_ids: string[], reason: string) =>
    post<{ confirmed: number }>("/fim/events/batch-confirm", { event_ids, reason }),

  // === 基线管理 ===
  listBaselines: (params: { page: number; page_size: number; policy_id?: string; host_id?: string; status?: string }) =>
    get<Paged<FimBaseline>>("/fim/baselines", params),
  getBaseline: (id: number, params?: { entry_page?: number; entry_page_size?: number }) =>
    get<{ baseline: FimBaseline; entries: FimBaselineEntry[]; entry_total: number }>(`/fim/baselines/${id}`, params),
  approveBaseline: (id: number) => post<void>(`/fim/baselines/${id}/approve`),
  batchApproveBaselines: (ids: number[]) => post<{ approved: number }>("/fim/baselines/batch-approve", { ids }),
  rejectBaseline: (id: number) => post<void>(`/fim/baselines/${id}/reject`),
};
