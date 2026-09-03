import { get, post } from "./client";
import type {
  HostMonitorData,
  ServiceMonitorData,
  ServiceAlertList,
  MonitorRange,
} from "./types";

interface ServiceAlertParams {
  page: number;
  page_size: number;
  search?: string;
  severity?: string;
  service?: string;
  status?: string;
}

export const monitorApi = {
  hostMetrics: (range: MonitorRange) => get<HostMonitorData>("/monitor/host", { range }),
  serviceMetrics: (range: MonitorRange) => get<ServiceMonitorData>("/monitor/services", { range }),
  listServiceAlerts: (params: ServiceAlertParams) =>
    get<ServiceAlertList>("/monitor/service-alerts", params),
  ackServiceAlert: (id: string) => post(`/monitor/service-alerts/${id}/ack`),
};
