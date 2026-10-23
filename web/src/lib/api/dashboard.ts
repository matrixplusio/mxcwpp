import { get } from "./client";
import type { DashboardStats } from "./types";
export const dashboardApi = { getStats: () => get<DashboardStats>("/dashboard/stats") };
