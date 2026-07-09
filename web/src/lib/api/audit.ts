import { get } from "./client";
import type { Paged, AuditLog } from "./types";

export const auditApi = {
  list: (params: {
    page: number; page_size: number;
    username?: string; resource_type?: string; action?: string;
    actor_type?: string; outcome?: string;
  }) => get<Paged<AuditLog>>("/audit-logs", params),
};
