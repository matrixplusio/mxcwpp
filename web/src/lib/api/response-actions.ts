import { get, post } from "./client";
import type { ResponseAction, OncallShift, OncallCurrent } from "./types";

export const responseActionsApi = {
  list: (params?: { status?: string }) =>
    get<{ items: ResponseAction[]; total: number }>("/response-actions", params),

  /** 审批通过。申请人不能审批自己的申请，后端会拒绝。 */
  approve: (id: number) => post(`/response-actions/${id}/approve`),
  /** 驳回。原因必填——否则申请人不知道该改什么。 */
  reject: (id: number, reason: string) => post(`/response-actions/${id}/reject`, { reason }),
  /** 执行已审批的处置。与审批分两步：审批是"同意做"，执行是"现在做"。 */
  execute: (id: number) => post(`/response-actions/${id}/execute`),
  rollback: (id: number) => post(`/response-actions/${id}/rollback`),
};

export const oncallApi = {
  current: () => get<OncallCurrent>("/oncall/current"),
  shifts: (days = 14) => get<{ items: OncallShift[]; total: number }>("/oncall/shifts", { days }),
  saveShift: (shift: {
    id?: number;
    tier: string;
    username: string;
    starts_at: string;
    ends_at: string;
  }) => post("/oncall/shifts", shift),
};
