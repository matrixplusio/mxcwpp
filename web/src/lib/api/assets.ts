import { get, post, put, del } from "./client";
import type {
  Paged,
  Host,
  HostPlugin,
  HostStatusDistribution,
  HostRiskDistribution,
  HostOSDistributionItem,
  AssetOverview,
  AssetStatistics,
  AssetTopItem,
  Process,
  Port,
  AssetUser,
  Software,
  Container,
  AppInfo,
  NetInterface,
  Volume,
  Kmod,
  Service,
  Cron,
  BusinessLine,
} from "./types";

// ===== 主机列表 =====
export const hostsApi = {
  list: (params: {
    page: number;
    page_size: number;
    os_family?: string;
    status?: string;
    business_line?: string;
    runtime_type?: "vm" | "docker" | "k8s";
    search?: string;
  }) => get<Paged<Host>>("/hosts", params),
  get: (hostId: string) => get<Host>(`/hosts/${hostId}`),
  plugins: (hostId: string) => get<HostPlugin[]>(`/hosts/${hostId}/plugins`),
  statusDistribution: () => get<HostStatusDistribution>("/hosts/status-distribution"),
  riskDistribution: () => get<HostRiskDistribution>("/hosts/risk-distribution"),
  osDistribution: () => get<HostOSDistributionItem[]>("/hosts/os-distribution"),
  updateTags: (hostId: string, tags: string[]) => put<void>(`/hosts/${hostId}/tags`, { tags }),
  updateBusinessLine: (hostId: string, business_line: string) =>
    put<void>(`/hosts/${hostId}/business-line`, { business_line }),
  restartAgent: (hostIds: string[]) => post<void>("/hosts/restart-agent", { host_ids: hostIds }),
  batchDelete: (hostIds: string[]) => post<void>("/hosts/batch-delete", { host_ids: hostIds }),
  batchUpdateBusinessLine: (hostIds: string[], business_line: string) =>
    post<void>("/hosts/batch-update-business-line", { host_ids: hostIds, business_line }),
  batchUpdateTags: (hostIds: string[], tags: string[]) =>
    post<void>("/hosts/batch-update-tags", { host_ids: hostIds, tags }),
};

// ===== 资产指纹 =====
interface FingerprintParams {
  host_id?: string;
  business_line?: string;
  page?: number;
  page_size?: number;
}

export const assetsApi = {
  overview: (params?: { host_id?: string; business_line?: string }) =>
    get<AssetOverview>("/assets/overview", params),
  statistics: (params?: { host_id?: string; business_line?: string }) =>
    get<AssetStatistics>("/assets/statistics", params),
  topN: (params: { type: string; host_id?: string; business_line?: string; limit?: number }) =>
    get<{ items: AssetTopItem[] }>("/assets/top", params),

  listProcesses: (params?: FingerprintParams) => get<Paged<Process>>("/assets/processes", params),
  listPorts: (params?: FingerprintParams & { protocol?: string }) =>
    get<Paged<Port>>("/assets/ports", params),
  listUsers: (params?: FingerprintParams) => get<Paged<AssetUser>>("/assets/users", params),
  listSoftware: (params?: FingerprintParams & { package_type?: string }) =>
    get<Paged<Software>>("/assets/software", params),
  listContainers: (params?: FingerprintParams & { runtime?: string; status?: string }) =>
    get<Paged<Container>>("/assets/containers", params),
  listApps: (params?: FingerprintParams & { app_type?: string }) =>
    get<Paged<AppInfo>>("/assets/apps", params),
  listNetInterfaces: (params?: FingerprintParams) =>
    get<Paged<NetInterface>>("/assets/network-interfaces", params),
  listVolumes: (params?: FingerprintParams) => get<Paged<Volume>>("/assets/volumes", params),
  listKmods: (params?: FingerprintParams) => get<Paged<Kmod>>("/assets/kmods", params),
  listServices: (params?: FingerprintParams & { service_type?: string; status?: string }) =>
    get<Paged<Service>>("/assets/services", params),
  listCrons: (params?: FingerprintParams & { user?: string; cron_type?: string }) =>
    get<Paged<Cron>>("/assets/crons", params),
};

// ===== 业务线管理 =====
export const businessLinesApi = {
  list: (params: { page: number; page_size: number; enabled?: string; keyword?: string }) =>
    get<Paged<BusinessLine>>("/business-lines", params),
  get: (id: number) => get<BusinessLine>(`/business-lines/${id}`),
  create: (body: {
    name: string;
    code: string;
    description?: string;
    owner?: string;
    contact?: string;
    enabled?: boolean;
  }) => post<BusinessLine>("/business-lines", body),
  update: (id: number, body: Partial<Omit<BusinessLine, "id" | "created_at" | "updated_at">>) =>
    put<BusinessLine>(`/business-lines/${id}`, body),
  delete: (id: number) => del<void>(`/business-lines/${id}`),
};
