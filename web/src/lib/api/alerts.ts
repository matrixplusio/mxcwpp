import { get, post, put, del } from "./client";
import type { Paged, Alert, AlertStatistics, AlertVerdict, AlertWhitelist, AlertWhitelistSuggestion } from "./types";

export interface ListAlertsParams {
  page?: number;
  page_size?: number;
  status?: string;
  severity?: string;
  host_id?: string;
  alert_type?: string;
  category?: string;
  business_line?: string;
  keyword?: string;
  start_time?: string;
  end_time?: string;
}

export interface WhitelistParams {
  name: string;
  rule_id?: string;
  host_id?: string;
  category?: string;
  severity?: string;
  exe?: string;
  cmdline?: string;
  source_ip_cidr?: string;
  reason?: string;
  /** 有效期天数：新建默认 90、最长 365；编辑时大于 0 表示从现在起续期 */
  expires_in_days?: number;
  /** 仅编辑时有效 */
  enabled?: boolean;
}

/** 关闭告警必须给出研判结论和原因 */
export interface CloseAlertBody {
  verdict: AlertVerdict;
  reason: string;
}

export const alertsApi = {
  list: (params: ListAlertsParams) => get<Paged<Alert>>("/alerts", params),
  get: (id: number) => get<Alert>(`/alerts/${id}`),
  statistics: () => get<AlertStatistics>("/alerts/statistics"),
  resolve: (id: number, body: CloseAlertBody) => post(`/alerts/${id}/resolve`, body),
  ignore: (id: number, body: CloseAlertBody) => post(`/alerts/${id}/ignore`, body),
};

export const whitelistApi = {
  list: (params: {
    page: number;
    page_size: number;
    keyword?: string;
    status?: "active" | "expired" | "disabled";
    expiring_days?: number;
  }) =>
    get<Paged<AlertWhitelist>>("/alerts/whitelist", params),
  create: (data: WhitelistParams) => post<AlertWhitelist>("/alerts/whitelist", data),
  update: (id: number, data: WhitelistParams) => put<AlertWhitelist>(`/alerts/whitelist/${id}`, data),
  delete: (id: number) => del(`/alerts/whitelist/${id}`),
};

export const suggestionApi = {
  list: (params: { page: number; page_size: number; status?: string }) =>
    get<Paged<AlertWhitelistSuggestion>>("/alerts/whitelist/suggestions", params),
  adopt: (id: number) => post(`/alerts/whitelist/suggestions/${id}/adopt`),
  dismiss: (id: number) => post(`/alerts/whitelist/suggestions/${id}/dismiss`),
  revoke: (id: number) => post(`/alerts/whitelist/suggestions/${id}/revoke`),
};
