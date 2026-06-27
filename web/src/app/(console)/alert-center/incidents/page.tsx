"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useUrlState } from "@/hooks/useUrlState";
import { incidentsApi } from "@/lib/api/incidents";
import type { Incident, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const knownSeverities: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (v: string): v is Severity => knownSeverities.includes(v as Severity);

export default function IncidentsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "active" });

  const statusOptions = [
    { label: t("alerts.incident.statusActive"), value: "active" },
    { label: t("alerts.incident.statusResolved"), value: "resolved" },
    { label: t("common.all"), value: "" },
  ];

  const { data, isLoading } = useQuery({
    queryKey: ["incidents", params],
    queryFn: () =>
      incidentsApi.list({
        page: params.page,
        page_size: params.page_size,
        status: params.status || undefined,
      }),
  });

  const [resolving, setResolving] = useState<Incident | null>(null);
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["incidents"] });

  const resolveMutation = useMutation({
    mutationFn: (id: string) => incidentsApi.resolve(id),
    onSuccess: () => {
      invalidate();
      setResolving(null);
      toast.success(t("alerts.incident.resolved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const columns: Column<Incident>[] = [
    {
      key: "title",
      title: t("alerts.incident.colTitle"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.title}</div>
          <div className="font-mono text-xs text-faint">{r.hostname || r.host_id}</div>
        </div>
      ),
    },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : "—"),
    },
    {
      key: "risk_score",
      title: t("alerts.incident.colRisk"),
      render: (r) => (
        <span className={r.risk_score >= 70 ? "font-semibold text-danger" : r.risk_score >= 40 ? "text-warning" : "text-ink"}>
          {r.risk_score}
        </span>
      ),
    },
    {
      key: "tactics",
      title: t("alerts.incident.colTactics"),
      render: (r) => <span className="font-mono text-xs">{r.tactic_count} 阶段 · {r.tactics || "—"}</span>,
    },
    {
      key: "alert_count",
      title: t("alerts.incident.colSignals"),
      render: (r) => (
        <span className="text-muted">
          {r.alert_count} 告警 / {r.behavior_alert_count} 行为
        </span>
      ),
    },
    { key: "last_seen_at", title: t("alerts.incident.colLastSeen"), render: (r) => <span className="text-faint">{r.last_seen_at}</span> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) =>
        r.status === "resolved" ? (
          <span className="text-faint">{t("alerts.incident.statusResolved")}</span>
        ) : (
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={() => setResolving(r)}
          >
            {t("alerts.incident.resolve")}
          </button>
        ),
    },
  ];

  return (
    <>
      <div className="space-y-4">
        <p className="text-sm text-muted">{t("alerts.incident.intro")}</p>
        <FilterBar>
          <Select
            value={params.status}
            onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))}
            options={statusOptions}
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("alerts.incident.empty")}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <ConfirmDialog
        open={!!resolving}
        title={t("alerts.incident.resolveTitle")}
        desc={resolving ? t("alerts.incident.resolveConfirmDesc", { title: resolving.title }) : undefined}
        loading={resolveMutation.isPending}
        onConfirm={() => resolving && resolveMutation.mutate(resolving.incident_id)}
        onCancel={() => setResolving(null)}
      />
    </>
  );
}
