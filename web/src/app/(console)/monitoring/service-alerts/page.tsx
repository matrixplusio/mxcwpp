"use client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { AlertOctagon, AlertTriangle, Bell, CheckCircle2 } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { monitorApi } from "@/lib/api/monitoring";
import type { ServiceAlert, ServiceAlertSeverity, ServiceAlertStatus } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { SearchInput } from "@/components/ui/SearchInput";
import { Select } from "@/components/ui/Select";
import { StatusTag } from "@/components/ui/Tag";
import { Button } from "@/components/ui/Button";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  search: string;
  severity: string;
  service: string;
  status: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const sevTone: Record<ServiceAlertSeverity, Tone> = { critical: "danger", warning: "warning", info: "info" };
const buildSevText = (t: TFunction): Record<ServiceAlertSeverity, string> => ({
  critical: t("monitoring.alerts.sevCritical"),
  warning: t("monitoring.alerts.sevWarning"),
  info: t("monitoring.alerts.sevInfo"),
});
const statusTone: Record<ServiceAlertStatus, Tone> = { firing: "danger", resolved: "success" };
const buildStatusText = (t: TFunction): Record<ServiceAlertStatus, string> => ({
  firing: t("monitoring.alerts.statusFiring"),
  resolved: t("monitoring.alerts.statusResolved"),
});

const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  { label: t("monitoring.alerts.sevCritical"), value: "critical" },
  { label: t("monitoring.alerts.sevWarning"), value: "warning" },
  { label: t("monitoring.alerts.sevInfo"), value: "info" },
];
const buildServiceOptions = (t: TFunction) => [
  { label: t("monitoring.alerts.allService"), value: "" },
  { label: "Manager", value: "manager" },
  { label: "AgentCenter", value: "agentcenter" },
  { label: "MySQL", value: "mysql" },
];
const buildStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("monitoring.alerts.statusFiring"), value: "firing" },
  { label: t("monitoring.alerts.statusResolved"), value: "resolved" },
];

export default function ServiceAlertPage() {
  const { t } = useTranslation();
  const sevText = buildSevText(t);
  const statusText = buildStatusText(t);
  const severityOptions = buildSeverityOptions(t);
  const serviceOptions = buildServiceOptions(t);
  const statusOptions = buildStatusOptions(t);
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    search: "",
    severity: "",
    service: "",
    status: "",
  });

  const { data, isLoading, isError } = useQuery({
    queryKey: ["mon-service-alerts", params],
    queryFn: () =>
      monitorApi.listServiceAlerts({
        page: params.page,
        page_size: params.page_size,
        search: params.search || undefined,
        severity: params.severity || undefined,
        service: params.service || undefined,
        status: params.status || undefined,
      }),
  });
  // 取不到就明说取不到：`?? 0` 会把"后端没答上来"渲染成 0，
  // 看板上读起来像"环境干净"。
  const statState = { error: isError, loading: isLoading };

  const ackMutation = useMutation({
    mutationFn: (id: string) => monitorApi.ackServiceAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mon-service-alerts"] });
      toast.success(t("monitoring.alerts.toastAcked"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const stats = data?.stats;

  const columns: Column<ServiceAlert>[] = [
    { key: "createdAt", title: t("monitoring.alerts.colCreatedAt"), render: (r) => <span className="text-faint tabular-nums">{r.createdAt}</span> },
    { key: "severity", title: t("common.level"), render: (r) => <StatusTag tone={sevTone[r.severity]}>{sevText[r.severity]}</StatusTag> },
    { key: "service", title: t("monitoring.alerts.colService"), render: (r) => <span className="font-medium text-ink">{r.service}</span> },
    {
      key: "message",
      title: t("monitoring.alerts.colMessage"),
      render: (r) => <span className="block max-w-md truncate text-muted">{r.message}</span>,
    },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={statusTone[r.status]}>{statusText[r.status]}</StatusTag> },
    {
      key: "resolvedAt",
      title: t("monitoring.alerts.colResolvedAt"),
      render: (r) => <span className="text-faint tabular-nums">{r.resolvedAt || "—"}</span>,
    },
    {
      key: "action",
      title: t("common.actions"),
      render: (r) => (
        <Button
          variant="ghost"
          className="h-8 px-3"
          disabled={r.status === "resolved" || ackMutation.isPending}
          onClick={() => ackMutation.mutate(r.id)}
        >
          {t("monitoring.alerts.ack")}
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("monitoring.alerts.statCritical")} value={stats?.critical ?? 0} {...statState} icon={AlertOctagon} tone="danger" />
        <StatCard compact label={t("monitoring.alerts.statWarning")} value={stats?.warning ?? 0} {...statState} icon={AlertTriangle} tone="warning" />
        <StatCard compact label={t("monitoring.alerts.statInfo")} value={stats?.info ?? 0} {...statState} icon={Bell} tone="default" />
        <StatCard compact label={t("monitoring.alerts.statResolved")} value={stats?.resolved ?? 0} {...statState} icon={CheckCircle2} tone="success" />
      </div>

      <FilterBar>
        <SearchInput
          value={params.search}
          onChange={(v) => setParams((p) => ({ ...p, search: v, page: 1 }))}
          placeholder={t("monitoring.alerts.search")}
        />
        <Select value={params.severity} onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))} options={severityOptions} />
        <Select value={params.service} onChange={(v) => setParams((p) => ({ ...p, service: v, page: 1 }))} options={serviceOptions} />
        <Select value={params.status} onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))} options={statusOptions} />
      </FilterBar>

      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.id}
          loading={isLoading}
          emptyText={t("monitoring.alerts.empty")}
        />
        <Pagination
          page={params.page}
          pageSize={params.page_size}
          total={data?.total ?? 0}
          onChange={(page) => setParams((p) => ({ ...p, page }))}
        />
      </Card>
    </div>
  );
}
