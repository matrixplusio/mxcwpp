import { get, post, put, del } from "./client";
import type {
  Paged,
  BaselinePolicy,
  BaselinePolicyList,
  BaselinePolicyStatistics,
  BaselineRule,
  PolicyGroup,
  BaselineTask,
  BaselineTaskChecks,
  BaselineFixItem,
  BaselineFixHistory,
} from "./types";

// 端点镜像 Vue（ui/src/api/policies.ts / policy-groups.ts / tasks.ts / fix.ts）。
export const baselineApi = {
  // ===== 基线检查（策略）=====
  // 注：/policies 返回 { items }（无 total）
  listPolicies: (params?: { os_family?: string; enabled?: boolean; group_id?: string }) =>
    get<BaselinePolicyList>("/policies", params),
  getPolicy: (policyId: string) => get<BaselinePolicy>(`/policies/${policyId}`),
  getPolicyStatistics: (policyId: string) =>
    get<BaselinePolicyStatistics>(`/policies/${policyId}/statistics`),
  createPolicy: (body: Partial<BaselinePolicy>) => post<BaselinePolicy>("/policies", body),
  updatePolicy: (policyId: string, body: Partial<BaselinePolicy>) =>
    put<BaselinePolicy>(`/policies/${policyId}`, body),
  deletePolicy: (policyId: string) => del<void>(`/policies/${policyId}`),
  batchEnablePolicies: (policyIds: string[], enabled: boolean) =>
    post<{ updated: number }>("/policies/batch/enable", { policy_ids: policyIds, enabled }),

  // ===== 基线规则（策略下的检查项）=====
  listRules: (policyId: string) => get<Paged<BaselineRule>>(`/policies/${policyId}/rules`),
  getRule: (ruleId: string) => get<BaselineRule>(`/rules/${ruleId}`),
  updateRule: (ruleId: string, body: Partial<BaselineRule>) => put<BaselineRule>(`/rules/${ruleId}`, body),
  deleteRule: (ruleId: string) => del<void>(`/rules/${ruleId}`),

  // ===== 策略组 =====
  listGroups: (params?: { with_policies?: boolean }) =>
    get<Paged<PolicyGroup>>("/policy-groups", params),
  getGroup: (id: string, params?: { with_policies?: boolean }) =>
    get<PolicyGroup>(`/policy-groups/${id}`, params),
  createGroup: (body: Partial<PolicyGroup>) => post<PolicyGroup>("/policy-groups", body),
  updateGroup: (id: string, body: Partial<PolicyGroup>) =>
    put<PolicyGroup>(`/policy-groups/${id}`, body),
  deleteGroup: (id: string) => del<void>(`/policy-groups/${id}`),

  // ===== 任务执行（基线扫描任务）=====
  listTasks: (params: { page: number; page_size: number; status?: string; policy_id?: string }) =>
    get<Paged<BaselineTask>>("/tasks", params),
  getTask: (taskId: string) => get<BaselineTask>(`/tasks/${taskId}`),
  getTaskChecks: (taskId: string, params?: { result?: string }) =>
    get<BaselineTaskChecks>(`/tasks/${taskId}/checks`, params),
  createTask: (body: Record<string, unknown>) => post<BaselineTask>("/tasks", body),
  runTask: (taskId: string) => post<BaselineTask>(`/tasks/${taskId}/run`),
  cancelTask: (taskId: string) => post<BaselineTask>(`/tasks/${taskId}/cancel`),
  deleteTask: (taskId: string) => del<void>(`/tasks/${taskId}`),

  // ===== 基线修复（可修复项）=====
  listFixItems: (params: {
    page: number;
    page_size: number;
    host_ids?: string[];
    business_line?: string;
    severities?: string[];
  }) => get<Paged<BaselineFixItem>>("/fix/fixable-items", params),
  createFixTask: (body: Record<string, unknown>) =>
    post<{ task_id: string }>("/fix-tasks", body),

  // ===== 修复历史（修复任务）=====
  listFixHistory: (params: { page: number; page_size: number; status?: string }) =>
    get<Paged<BaselineFixHistory>>("/fix-tasks", params),
  getFixHistory: (taskId: string) => get<BaselineFixHistory>(`/fix-tasks/${taskId}`),
  cancelFixTask: (taskId: string) => post<void>(`/fix-tasks/${taskId}/cancel`),
  deleteFixTask: (taskId: string) => del<void>(`/fix-tasks/${taskId}`),
};
