"use client";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Server, Wifi, WifiOff, ArrowUpCircle, AlertTriangle, PackageX } from "lucide-react";
import { operationsApi } from "@/lib/api/operations";
import type { InspectionHostItem } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag } from "@/components/ui/Tag";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { toast } from "@/components/ui/toast";

export default function InspectionPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["ops-inspection"],
    queryFn: () => operationsApi.inspectionOverview(),
  });

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [agentFilter, setAgentFilter] = useState("");
  const [blFilter, setBlFilter] = useState("");
  const [pluginFilter, setPluginFilter] = useState("");
  const [restarting, setRestarting] = useState<InspectionHostItem | null>(null);

  const restartMutation = useMutation({
    mutationFn: (hostId: string) => operationsApi.restartAgent(hostId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ops-inspection"] });
      setRestarting(null);
      toast.success(t("operations.inspection.restartDone"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const summary = data?.summary;
  const latestAgentVersion = data?.latest_agent_version;

  const allHosts = useMemo(() => data?.hosts ?? [], [data]);
  const businessLineOptions = useMemo(() => {
    const set = new Set<string>();
    allHosts.forEach((h) => h.business_line && set.add(h.business_line));
    return [
      { label: t("operations.inspection.allBusinessLine"), value: "" },
      ...Array.from(set).sort().map((bl) => ({ label: bl, value: bl })),
    ];
  }, [allHosts, t]);

  const pluginOptions = [
    { label: t("operations.inspection.pluginAll"), value: "" },
    { label: t("operations.inspection.pluginError"), value: "error" },
    { label: t("operations.inspection.pluginOutdated"), value: "outdated" },
  ];

  const hosts = useMemo(() => {
    const kw = search.trim().toLowerCase();
    return allHosts.filter((h) => {
      if (statusFilter && h.status !== statusFilter) return false;
      if (blFilter && h.business_line !== blFilter) return false;
      if (agentFilter === "outdated" && !(h.agent_version && latestAgentVersion && h.agent_version !== latestAgentVersion)) return false;
      if (agentFilter === "latest" && h.agent_version !== latestAgentVersion) return false;
      if (pluginFilter === "error" && !h.plugins?.some((p) => p.status === "error" || p.status === "stopped")) return false;
      if (pluginFilter === "outdated" && !h.plugins?.some((p) => p.need_update)) return false;
      if (kw) {
        const hay = `${h.hostname} ${h.host_id} ${h.ipv4?.join(" ") ?? ""}`.toLowerCase();
        if (!hay.includes(kw)) return false;
      }
      return true;
    });
  }, [allHosts, search, statusFilter, agentFilter, blFilter, pluginFilter, latestAgentVersion]);

  const statusOptions = [
    { label: t("operations.inspection.allStatus"), value: "" },
    { label: t("common.online"), value: "online" },
    { label: t("common.offline"), value: "offline" },
  ];
  const agentOptions = [
    { label: t("operations.inspection.agentAll"), value: "" },
    { label: t("operations.inspection.agentOutdated"), value: "outdated" },
    { label: t("operations.inspection.agentLatest"), value: "latest" },
  ];

  const columns: Column<InspectionHostItem>[] = [
    {
      key: "hostname",
      title: t("operations.inspection.colHost"),
      render: (r) => (
        <div className="min-w-0">
          <div className="font-medium text-ink">{r.hostname || "—"}</div>
          <div className="text-xs text-faint truncate">{r.host_id}</div>
        </div>
      ),
    },
    {
      key: "ipv4",
      title: t("operations.inspection.colIp"),
      render: (r) => <span className="text-muted">{r.ipv4?.length ? r.ipv4.join(", ") : "—"}</span>,
    },
    {
      key: "status",
      title: t("operations.inspection.colStatus"),
      render: (r) =>
        r.status === "online" ? (
          <StatusTag tone="success">{t("common.online")}</StatusTag>
        ) : (
          <StatusTag tone="neutral">{t("common.offline")}</StatusTag>
        ),
    },
    {
      key: "agent_version",
      title: t("operations.inspection.colAgentVersion"),
      render: (r) => (
        <span className="flex items-center gap-2">
          <span className="font-mono text-ink">{r.agent_version || "—"}</span>
          {latestAgentVersion && r.agent_version && r.agent_version !== latestAgentVersion && (
            <StatusTag tone="warning">{t("operations.inspection.tagOutdated")}</StatusTag>
          )}
        </span>
      ),
    },
    {
      key: "last_heartbeat",
      title: t("operations.inspection.colLastHeartbeat"),
      render: (r) => <span className="text-faint tabular-nums">{r.last_heartbeat || "—"}</span>,
    },
    {
      key: "plugins",
      title: t("operations.inspection.colPlugins"),
      render: (r) => <span className="text-muted">{t("operations.inspection.pluginCount", { n: r.plugins?.length ?? 0 })}</span>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end">
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink disabled:cursor-not-allowed disabled:opacity-40"
            disabled={r.status !== "online"}
            onClick={(e) => {
              e.stopPropagation();
              setRestarting(r);
            }}
          >
            {t("operations.inspection.restartAgent")}
          </button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-4 mb-5 lg:grid-cols-6">
        <StatCard label={t("operations.inspection.statTotal")} value={summary?.total_hosts ?? 0} icon={Server} />
        <StatCard label={t("operations.inspection.statOnline")} value={summary?.online_hosts ?? 0} icon={Wifi} tone="success" />
        <StatCard label={t("operations.inspection.statOffline")} value={summary?.offline_hosts ?? 0} icon={WifiOff} tone="warning" />
        <StatCard label={t("operations.inspection.statAgentOutdated")} value={summary?.agent_outdated_count ?? 0} icon={ArrowUpCircle} tone="warning" />
        <StatCard label={t("operations.inspection.statPluginError")} value={summary?.plugin_error_count ?? 0} icon={AlertTriangle} tone="danger" />
        <StatCard label={t("operations.inspection.statPluginOutdated")} value={summary?.plugin_outdated_count ?? 0} icon={PackageX} tone="warning" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder={t("operations.inspection.search")}
          />
          <Select value={statusFilter} onChange={setStatusFilter} options={statusOptions} />
          <Select value={agentFilter} onChange={setAgentFilter} options={agentOptions} />
          <Select value={pluginFilter} onChange={setPluginFilter} options={pluginOptions} />
          <Select value={blFilter} onChange={setBlFilter} options={businessLineOptions} />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={hosts}
            rowKey={(r) => r.host_id}
            loading={isLoading}
            emptyText={t("operations.inspection.empty")}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={!!restarting}
        title={t("operations.inspection.restartTitle")}
        desc={restarting ? t("operations.inspection.restartConfirmDesc", { name: restarting.hostname || restarting.host_id }) : undefined}
        danger={false}
        confirmText={t("operations.inspection.restartConfirm")}
        loading={restartMutation.isPending}
        onConfirm={() => restarting && restartMutation.mutate(restarting.host_id)}
        onCancel={() => setRestarting(null)}
      />
    </>
  );
}
