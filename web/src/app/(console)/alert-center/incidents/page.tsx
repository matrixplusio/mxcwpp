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
import { Drawer } from "@/components/ui/Drawer";
import { SeverityTag, StatusTag } from "@/components/ui/Tag";
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
  const [detailId, setDetailId] = useState<string | null>(null);
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["incidents"] });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ["incident-detail", detailId],
    queryFn: () => incidentsApi.get(detailId!),
    enabled: !!detailId,
  });

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
          <button
            type="button"
            className="text-left font-medium text-ink transition-colors hover:text-primary"
            onClick={() => setDetailId(r.incident_id)}
          >
            {r.title}
          </button>
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

      <Drawer open={!!detailId} onClose={() => setDetailId(null)} width={680} title={t("alerts.incident.detailTitle")}>
        {detailLoading ? (
          <p className="text-sm text-muted">{t("common.loading")}</p>
        ) : detail ? (
          <div className="space-y-5">
            {/* 叙事概述 */}
            <div className="rounded-md border border-line bg-surface-muted p-4">
              <div className="mb-2 flex items-center gap-2">
                {isSeverity(detail.incident.severity) && <SeverityTag level={detail.incident.severity} />}
                <span className="text-sm font-semibold text-danger">
                  {t("alerts.incident.colRisk")} {detail.incident.risk_score}/100
                </span>
              </div>
              <p className="text-sm leading-relaxed text-ink">{detail.narrative}</p>
            </div>

            {/* 攻击阶段(kill-chain) */}
            {detail.stages && detail.stages.length > 0 && (
              <div>
                <div className="mb-2 text-xs font-medium text-faint">{t("alerts.incident.attackStages")}</div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {detail.stages.map((s, i) => (
                    <span key={s.category} className="flex items-center gap-1.5">
                      {i > 0 && <span className="text-faint">→</span>}
                      <span className="rounded-full border border-line bg-surface px-2.5 py-1 text-xs text-ink">
                        {s.name} <span className="text-faint">×{s.alert_count}</span>
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* 处置建议 */}
            {detail.recommendations && detail.recommendations.length > 0 && (
              <div>
                <div className="mb-2 text-xs font-medium text-faint">{t("alerts.incident.recommendations")}</div>
                <ul className="list-inside list-disc space-y-1 text-sm text-muted">
                  {detail.recommendations.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* 告警时间线 */}
            <div>
              <div className="mb-2 text-xs font-medium text-faint">
                {t("alerts.incident.timeline")} ({detail.alerts.length})
              </div>
              <div className="space-y-2">
                {detail.alerts.map((a) => (
                  <div key={a.id} className="rounded-md border border-line p-3 text-sm">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-ink">{a.title || a.rule_id}</span>
                      <span className="text-faint tabular-nums">{a.first_seen_at}</span>
                    </div>
                    <div className="mt-1 flex items-center gap-2 text-xs">
                      {isSeverity(a.severity) && <SeverityTag level={a.severity} />}
                      {a.category && <StatusTag tone="neutral">{a.category}</StatusTag>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </Drawer>

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
