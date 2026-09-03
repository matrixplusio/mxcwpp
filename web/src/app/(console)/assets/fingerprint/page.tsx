"use client";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  Server,
  CheckCircle2,
  AlertTriangle,
  Wifi,
  WifiOff,
  Layers,
} from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { assetsApi } from "@/lib/api/assets";
import type {
  Paged,
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
} from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag } from "@/components/ui/Tag";
import { Tabs } from "@/components/ui/Tabs";

interface FetchParams {
  host_id?: string;
  page?: number;
  page_size?: number;
}

// Each tab keeps its own real entity type via a generic config; the array
// stores them with erased row types so we can iterate uniformly.
interface TabConfig<T> {
  key: string;
  label: string;
  columns: Column<T>[];
  fetch: (params: FetchParams) => Promise<Paged<T>>;
  rowId: (row: T) => string;
}

function defineTab<T>(cfg: TabConfig<T>): TabConfig<unknown> {
  return cfg as unknown as TabConfig<unknown>;
}

const mono = "font-mono text-xs text-muted";
const truncate = "block max-w-[280px] truncate";

const dash = (v: string | number | undefined | null) =>
  v === undefined || v === null || v === "" ? "—" : v;

function buildTabs(t: TFunction): TabConfig<unknown>[] {
  const hostCol = <T extends { host_id: string }>(): Column<T> => ({
    key: "host_id",
    title: t("assets.fingerprint.colHostId"),
    render: (r) => <span className="font-mono text-xs text-ink">{r.host_id || "—"}</span>,
  });

  return [
    defineTab<Port>({
      key: "ports",
      label: t("assets.fingerprint.tabPorts"),
      fetch: assetsApi.listPorts,
      rowId: (r) => `${r.host_id}-${r.protocol}-${r.port}`,
      columns: [
        hostCol<Port>(),
        { key: "protocol", title: t("assets.fingerprint.colProtocol"), render: (r) => dash(r.protocol) },
        { key: "port", title: t("assets.fingerprint.colPort"), render: (r) => <span className="tabular-nums">{r.port}</span> },
        { key: "process_name", title: t("assets.fingerprint.colProcess"), render: (r) => dash(r.process_name) },
        { key: "pid", title: "PID", render: (r) => <span className={mono}>{dash(r.pid)}</span> },
        {
          key: "state",
          title: t("common.status"),
          render: (r) => (r.state ? <StatusTag tone="info">{r.state}</StatusTag> : "—"),
        },
      ],
    }),
    defineTab<Process>({
      key: "processes",
      label: t("assets.fingerprint.tabProcesses"),
      fetch: assetsApi.listProcesses,
      rowId: (r) => `${r.host_id}-${r.pid}`,
      columns: [
        hostCol<Process>(),
        { key: "pid", title: "PID", render: (r) => <span className={mono}>{dash(r.pid)}</span> },
        { key: "exe", title: t("assets.fingerprint.colExe"), render: (r) => <span className={mono}>{dash(r.exe)}</span> },
        {
          key: "cmdline",
          title: t("assets.fingerprint.colCmdline"),
          render: (r) => (
            <span className={`${mono} ${truncate}`} title={r.cmdline}>
              {dash(r.cmdline)}
            </span>
          ),
        },
        { key: "username", title: t("assets.fingerprint.colUser"), render: (r) => dash(r.username) },
        { key: "collected_at", title: t("assets.fingerprint.colCollectedAt"), render: (r) => <span className="text-faint tabular-nums">{dash(r.collected_at)}</span> },
      ],
    }),
    defineTab<AssetUser>({
      key: "users",
      label: t("assets.fingerprint.tabUsers"),
      fetch: assetsApi.listUsers,
      rowId: (r) => `${r.host_id}-${r.username}`,
      columns: [
        hostCol<AssetUser>(),
        { key: "username", title: t("assets.fingerprint.colUsername"), render: (r) => <span className="font-medium text-ink">{dash(r.username)}</span> },
        { key: "uid", title: "UID", render: (r) => <span className={mono}>{dash(r.uid)}</span> },
        { key: "gid", title: "GID", render: (r) => <span className={mono}>{dash(r.gid)}</span> },
        { key: "shell", title: "Shell", render: (r) => <span className={mono}>{dash(r.shell)}</span> },
        { key: "home_dir", title: t("assets.fingerprint.colHome"), render: (r) => <span className={mono}>{dash(r.home_dir)}</span> },
      ],
    }),
    defineTab<Software>({
      key: "software",
      label: t("assets.fingerprint.tabSoftware"),
      fetch: assetsApi.listSoftware,
      rowId: (r) => `${r.host_id}-${r.name}-${r.version ?? ""}`,
      columns: [
        hostCol<Software>(),
        { key: "name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{dash(r.name)}</span> },
        { key: "version", title: t("common.version"), render: (r) => <span className={mono}>{dash(r.version)}</span> },
        {
          key: "package_type",
          title: t("common.type"),
          render: (r) => (r.package_type ? <StatusTag tone="neutral">{r.package_type}</StatusTag> : "—"),
        },
        { key: "vendor", title: t("assets.fingerprint.colVendor"), render: (r) => dash(r.vendor) },
      ],
    }),
    defineTab<Container>({
      key: "containers",
      label: t("assets.fingerprint.tabContainers"),
      fetch: assetsApi.listContainers,
      rowId: (r) => `${r.host_id}-${r.container_id}`,
      columns: [
        hostCol<Container>(),
        { key: "container_name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{dash(r.container_name)}</span> },
        {
          key: "image",
          title: t("assets.fingerprint.colImage"),
          render: (r) => (
            <span className={`${mono} ${truncate}`} title={r.image}>
              {dash(r.image)}
            </span>
          ),
        },
        { key: "runtime", title: t("assets.fingerprint.colRuntime"), render: (r) => dash(r.runtime) },
        {
          key: "status",
          title: t("common.status"),
          render: (r) =>
            r.status ? (
              <StatusTag tone={r.status.toLowerCase().includes("run") ? "success" : "neutral"}>{r.status}</StatusTag>
            ) : (
              "—"
            ),
        },
      ],
    }),
    defineTab<AppInfo>({
      key: "apps",
      label: t("assets.fingerprint.tabApps"),
      fetch: assetsApi.listApps,
      rowId: (r) => `${r.host_id}-${r.app_type}-${r.app_name ?? ""}`,
      columns: [
        hostCol<AppInfo>(),
        { key: "app_name", title: t("common.name"), render: (r) => <span className="font-medium text-ink">{dash(r.app_name)}</span> },
        {
          key: "app_type",
          title: t("common.type"),
          render: (r) => (r.app_type ? <StatusTag tone="info">{r.app_type}</StatusTag> : "—"),
        },
        { key: "version", title: t("common.version"), render: (r) => <span className={mono}>{dash(r.version)}</span> },
        { key: "port", title: t("assets.fingerprint.colPort"), render: (r) => <span className="tabular-nums">{dash(r.port)}</span> },
      ],
    }),
    defineTab<NetInterface>({
      key: "network-interfaces",
      label: t("assets.fingerprint.tabNetwork"),
      fetch: assetsApi.listNetInterfaces,
      rowId: (r) => `${r.host_id}-${r.interface_name}`,
      columns: [
        hostCol<NetInterface>(),
        { key: "interface_name", title: t("assets.fingerprint.colInterfaceName"), render: (r) => <span className="font-medium text-ink">{dash(r.interface_name)}</span> },
        { key: "mac_address", title: "MAC", render: (r) => <span className={mono}>{dash(r.mac_address)}</span> },
        {
          key: "ipv4_addresses",
          title: "IPv4",
          render: (r) => <span className={mono}>{r.ipv4_addresses?.length ? r.ipv4_addresses.join(", ") : "—"}</span>,
        },
        {
          key: "state",
          title: t("common.status"),
          render: (r) =>
            r.state ? (
              <StatusTag tone={r.state.toLowerCase() === "up" ? "success" : "neutral"}>{r.state}</StatusTag>
            ) : (
              "—"
            ),
        },
      ],
    }),
    defineTab<Volume>({
      key: "volumes",
      label: t("assets.fingerprint.tabVolumes"),
      fetch: assetsApi.listVolumes,
      rowId: (r) => `${r.host_id}-${r.device ?? r.mount_point ?? ""}`,
      columns: [
        hostCol<Volume>(),
        { key: "device", title: t("assets.fingerprint.colDevice"), render: (r) => <span className={mono}>{dash(r.device)}</span> },
        { key: "mount_point", title: t("assets.fingerprint.colMountPoint"), render: (r) => <span className={mono}>{dash(r.mount_point)}</span> },
        { key: "file_system", title: t("assets.fingerprint.colFileSystem"), render: (r) => dash(r.file_system) },
        {
          key: "usage_percent",
          title: t("assets.fingerprint.colUsage"),
          render: (r) =>
            r.usage_percent === undefined ? (
              "—"
            ) : (
              <StatusTag tone={r.usage_percent >= 85 ? "warning" : "neutral"}>{r.usage_percent}%</StatusTag>
            ),
        },
      ],
    }),
    defineTab<Kmod>({
      key: "kmods",
      label: t("assets.fingerprint.tabKmods"),
      fetch: assetsApi.listKmods,
      rowId: (r) => `${r.host_id}-${r.module_name}`,
      columns: [
        hostCol<Kmod>(),
        { key: "module_name", title: t("assets.fingerprint.colModuleName"), render: (r) => <span className="font-medium text-ink">{dash(r.module_name)}</span> },
        { key: "size", title: t("assets.fingerprint.colSize"), render: (r) => <span className="tabular-nums">{dash(r.size)}</span> },
        { key: "used_by", title: t("assets.fingerprint.colUsedBy"), render: (r) => <span className="tabular-nums">{dash(r.used_by)}</span> },
        { key: "state", title: t("common.status"), render: (r) => dash(r.state) },
      ],
    }),
    defineTab<Service>({
      key: "services",
      label: t("assets.fingerprint.tabServices"),
      fetch: assetsApi.listServices,
      rowId: (r) => `${r.host_id}-${r.service_name}`,
      columns: [
        hostCol<Service>(),
        { key: "service_name", title: t("assets.fingerprint.colServiceName"), render: (r) => <span className="font-medium text-ink">{dash(r.service_name)}</span> },
        { key: "service_type", title: t("common.type"), render: (r) => dash(r.service_type) },
        {
          key: "status",
          title: t("common.status"),
          render: (r) =>
            r.status ? (
              <StatusTag tone={r.status.toLowerCase().includes("run") || r.status.toLowerCase() === "active" ? "success" : "neutral"}>
                {r.status}
              </StatusTag>
            ) : (
              "—"
            ),
        },
      ],
    }),
    defineTab<Cron>({
      key: "crons",
      label: t("assets.fingerprint.tabCrons"),
      fetch: assetsApi.listCrons,
      rowId: (r) => `${r.host_id}-${r.user}-${r.schedule}`,
      columns: [
        hostCol<Cron>(),
        { key: "user", title: t("assets.fingerprint.colUser"), render: (r) => dash(r.user) },
        { key: "schedule", title: t("assets.fingerprint.colSchedule"), render: (r) => <span className={mono}>{dash(r.schedule)}</span> },
        {
          key: "command",
          title: t("assets.fingerprint.colCommand"),
          render: (r) => (
            <span className={`${mono} ${truncate}`} title={r.command}>
              {dash(r.command)}
            </span>
          ),
        },
      ],
    }),
  ];
}

export default function FingerprintPage() {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState("ports");
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, host_id: "" });

  const tabs = useMemo(() => buildTabs(t), [t]);
  const tabItems = tabs.map((tab) => ({ key: tab.key, label: tab.label }));

  const overviewQuery = useQuery({
    queryKey: ["asset-overview"],
    queryFn: () => assetsApi.overview(),
  });
  const ov = overviewQuery.data;
  // 概览取不到时不得渲染成 0，否则"0 台未覆盖"读起来像资产全都纳管了。
  const ovState = { error: overviewQuery.isError, loading: overviewQuery.isLoading };

  const current = tabs.find((tab) => tab.key === activeTab) ?? tabs[0];

  const { data, isLoading } = useQuery({
    queryKey: ["asset-fp", activeTab, params],
    queryFn: () => current.fetch(params),
  });

  const onTabChange = (key: string) => {
    setActiveTab(key);
    setParams({ page: 1, page_size: 20, host_id: "" });
  };

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <StatCard compact label={t("assets.fingerprint.statManaged")} value={ov?.total_hosts ?? 0} {...ovState} icon={Server} />
        <StatCard compact label={t("assets.fingerprint.statCovered")} value={ov?.covered_hosts ?? 0} {...ovState} icon={CheckCircle2} tone="success" />
        <StatCard compact label={t("assets.fingerprint.statUncovered")} value={ov?.uncovered_hosts ?? 0} {...ovState} icon={AlertTriangle} tone="warning" />
        <StatCard compact label={t("common.online")} value={ov?.online_hosts ?? 0} {...ovState} icon={Wifi} tone="success" />
        <StatCard compact label={t("common.offline")} value={ov?.offline_hosts ?? 0} {...ovState} icon={WifiOff} tone="warning" />
        <StatCard compact label={t("assets.fingerprint.statBusinessLines")} value={ov?.business_line_count ?? 0} {...ovState} icon={Layers} />
      </div>

      <Tabs items={tabItems} active={activeTab} onChange={onTabChange} />

      <Card>
        <div className="mb-4">
          <FilterBar>
            <SearchInput
              value={params.host_id ?? ""}
              onChange={(v) => setParams((p) => ({ ...p, host_id: v, page: 1 }))}
              placeholder={t("assets.fingerprint.filterPlaceholder")}
            />
          </FilterBar>
        </div>
        <DataTable
          columns={current.columns}
          rows={data?.items ?? []}
          rowKey={(r) => current.rowId(r)}
          loading={isLoading}
          emptyText={t("common.noData")}
        />
        <Pagination
          page={params.page ?? 1}
          pageSize={params.page_size ?? 20}
          total={data?.total ?? 0}
          onChange={(page) => setParams((p) => ({ ...p, page }))}
        />
      </Card>
    </div>
  );
}
