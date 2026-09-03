import { get, post } from "./client";
import type { Paged, Incident, IncidentDetail, IncidentEvent, IncidentVerdict } from "./types";

export const incidentsApi = {
  list: (params: { page: number; page_size: number; status?: string; host_id?: string }) =>
    get<Paged<Incident>>("/incidents", params),
  get: (id: string) => get<IncidentDetail>(`/incidents/${id}`),
  timeline: (id: string) =>
    get<{ items: IncidentEvent[]; total: number }>(`/incidents/${id}/timeline`),

  assign: (id: string, owner: string) => post(`/incidents/${id}/assign`, { owner }),
  ack: (id: string) => post(`/incidents/${id}/ack`),
  comment: (id: string, body: string, ref?: string) =>
    post(`/incidents/${id}/comments`, { body, ref }),
  escalate: (id: string, to: string, reason: string) =>
    post(`/incidents/${id}/escalate`, { to, reason }),

  /**
   * 关闭事件。verdict 与 reason 均必填——后端会拒绝缺任一项的请求。
   *
   * 没有结论就无法回答"这条是不是真威胁"，而研判结论是检测质量的唯一可信来源：
   * 拿已关闭数量当 precision，会把"没人看所以批量关掉"算成检测准确。
   */
  resolve: (id: string, verdict: IncidentVerdict, reason: string) =>
    post(`/incidents/${id}/resolve`, { verdict, reason }),
};
