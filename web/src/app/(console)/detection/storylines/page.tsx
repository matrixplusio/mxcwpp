"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { GitBranch, Activity, AlertTriangle } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { detectionApi } from "@/lib/api/detection";
import type { Storyline, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatCard } from "@/components/ui/StatCard";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  severity: string;
  status: string;
  host_id: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const buildStatusLabel = (t: TFunction): Record<string, string> => ({
  active: t("detection.storylines.statusActive"),
  investigating: t("detection.storylines.statusInvestigating"),
  resolved: t("detection.storylines.statusResolved"),
});

const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  { label: t("common.severity.critical"), value: "critical" },
  { label: t("common.severity.high"), value: "high" },
  { label: t("common.severity.medium"), value: "medium" },
  { label: t("common.severity.low"), value: "low" },
];
const buildStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("detection.storylines.statusActive"), value: "active" },
  { label: t("detection.storylines.statusInvestigating"), value: "investigating" },
  { label: t("detection.storylines.statusResolved"), value: "resolved" },
];

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
function isSeverity(v: string): v is Severity {
  return (SEVERITIES as string[]).includes(v);
}

function statusTone(status: string): Tone {
  if (status === "active") return "danger";
  if (status === "resolved") return "success";
  return "neutral";
}

function riskColor(score: number): string {
  if (score >= 80) return "text-danger";
  if (score >= 50) return "text-warning";
  return "text-ink";
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-24 shrink-0 text-muted">{label}</span>
      <span className="min-w-0 break-all text-ink">{value}</span>
    </div>
  );
}

export default function StorylinesPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const STATUS_LABEL = buildStatusLabel(t);
  const severityOptions = buildSeverityOptions(t);
  const statusOptions = buildStatusOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    severity: "",
    status: "",
    host_id: "",
  });

  const { data: stats } = useQuery({
    queryKey: ["storyline-stats"],
    queryFn: () => detectionApi.storylineStats(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["storylines", params],
    queryFn: () =>
      detectionApi.listStorylines({
        page: params.page,
        page_size: params.page_size,
        severity: params.severity || undefined,
        status: params.status || undefined,
        host_id: params.host_id || undefined,
      }),
  });

  const [detail, setDetail] = useState<Storyline | null>(null);
  const [resolving, setResolving] = useState<Storyline | null>(null);

  // 拉故事线完整内容(关联事件链)
  const { data: detailData } = useQuery({
    queryKey: ["storyline-detail", detail?.story_id],
    queryFn: () => detectionApi.getStoryline(detail!.story_id, { page: 1, page_size: 100 }),
    enabled: !!detail,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["storylines"] });
    queryClient.invalidateQueries({ queryKey: ["storyline-stats"] });
  };

  const resolveMutation = useMutation({
    mutationFn: (storyId: string) => detectionApi.resolveStoryline(storyId),
    onSuccess: () => {
      invalidate();
      setResolving(null);
      setDetail(null);
      toast.success(t("detection.storylines.resolved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const ruleList = (raw: string) =>
    raw
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);

  const columns: Column<Storyline>[] = [
    { key: "story_id", title: t("detection.storylines.colStoryId"), render: (r) => <span className="font-mono text-xs text-ink">{r.story_id}</span> },
    { key: "hostname", title: t("detection.storylines.colHost"), render: (r) => <span className="font-medium text-ink">{r.hostname || r.host_id}</span> },
    { key: "phase", title: t("detection.storylines.colPhase"), render: (r) => <StatusTag tone="neutral">{r.phase}</StatusTag> },
    { key: "severity", title: t("common.level"), render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>) },
    { key: "risk_score", title: t("detection.storylines.colRiskScore"), render: (r) => <span className={`font-semibold tabular-nums ${riskColor(r.risk_score)}`}>{r.risk_score}</span> },
    { key: "event_count", title: t("detection.storylines.colEventCount"), render: (r) => <span className="tabular-nums text-ink">{r.event_count}</span> },
    { key: "alert_count", title: t("detection.storylines.colAlertCount"), render: (r) => <span className="tabular-nums text-ink">{r.alert_count}</span> },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={statusTone(r.status)}>{STATUS_LABEL[r.status] ?? r.status}</StatusTag> },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" className="h-8 px-3" onClick={() => setDetail(r)}>
            {t("common.details")}
          </Button>
          <Button variant="ghost" className="h-8 px-3" disabled={r.status !== "active"} onClick={() => setResolving(r)}>
            {t("detection.storylines.actionResolve")}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 mb-5">
        <StatCard compact label={t("detection.storylines.statTotal")} value={stats?.total ?? 0} icon={GitBranch} tone="default" />
        <StatCard compact label={t("detection.storylines.statActive")} value={stats?.active ?? 0} icon={Activity} tone="warning" />
        <StatCard compact label={t("detection.storylines.statCriticalActive")} value={stats?.critical_active ?? 0} icon={AlertTriangle} tone="danger" />
      </div>

      <div className="space-y-4">
        <FilterBar>
          <Select
            value={params.severity}
            onChange={(v) => setParams((p) => ({ ...p, severity: v, page: 1 }))}
            options={severityOptions}
          />
          <Select
            value={params.status}
            onChange={(v) => setParams((p) => ({ ...p, status: v, page: 1 }))}
            options={statusOptions}
          />
          <Input
            value={params.host_id}
            onChange={(e) => setParams((p) => ({ ...p, host_id: e.target.value, page: 1 }))}
            placeholder={t("detection.storylines.filterHostId")}
            className="w-56"
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.story_id}
            loading={isLoading}
            emptyText={t("detection.storylines.empty")}
            onRowClick={setDetail}
          />
          <Pagination
            page={params.page}
            pageSize={params.page_size}
            total={data?.total ?? 0}
            onChange={(page) => setParams((p) => ({ ...p, page }))}
          />
        </Card>
      </div>

      <Drawer
        open={!!detail}
        onClose={() => setDetail(null)}
        title={t("detection.storylines.detailTitle")}
        width={560}
        footer={
          detail?.status === "active" ? <Button onClick={() => detail && setResolving(detail)}>{t("detection.storylines.actionResolve")}</Button> : undefined
        }
      >
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                {isSeverity(detail.severity) ? <SeverityTag level={detail.severity} /> : <StatusTag tone="neutral">{detail.severity}</StatusTag>}
                <StatusTag tone={statusTone(detail.status)}>{STATUS_LABEL[detail.status] ?? detail.status}</StatusTag>
              </div>
            </div>

            <div className="space-y-2">
              <Field label={t("detection.storylines.fieldStoryId")} value={<span className="font-mono text-xs">{detail.story_id}</span>} />
              <Field label={t("detection.storylines.fieldHost")} value={detail.hostname || detail.host_id} />
              <Field label={t("detection.storylines.fieldPhase")} value={detail.phase} />
              <Field label={t("detection.storylines.fieldRiskScore")} value={<span className={`font-semibold tabular-nums ${riskColor(detail.risk_score)}`}>{detail.risk_score}</span>} />
              <Field label={t("detection.storylines.fieldEventCount")} value={<span className="tabular-nums">{detail.event_count}</span>} />
              <Field label={t("detection.storylines.fieldAlertCount")} value={<span className="tabular-nums">{detail.alert_count}</span>} />
              <Field label={t("detection.storylines.fieldFirstSeen")} value={<span className="tabular-nums">{detail.first_seen_at}</span>} />
              <Field label={t("detection.storylines.fieldLastSeen")} value={<span className="tabular-nums">{detail.last_seen_at}</span>} />
            </div>

            {detail.summary && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("detection.storylines.summary")}</div>
                <p className="text-sm leading-relaxed text-muted">{detail.summary}</p>
              </div>
            )}

            {ruleList(detail.rule_names).length > 0 && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("detection.storylines.ruleNames")}</div>
                <ul className="space-y-1">
                  {ruleList(detail.rule_names).map((name, i) => (
                    <li key={i} className="rounded-control bg-surface-muted px-3 py-2 text-sm text-ink">{name}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* 关联事件链(实际内容) */}
            <div>
              <div className="mb-1.5 text-sm font-medium text-ink">
                {t("detection.storylines.eventChain")} ({detailData?.events_total ?? 0})
              </div>
              {(detailData?.events?.length ?? 0) === 0 ? (
                <p className="text-sm text-muted">{t("detection.storylines.noEvents")}</p>
              ) : (
                <div className="space-y-2">
                  {detailData!.events.map((ev) => (
                    <div key={ev.id} className="rounded-md border border-line p-3 text-sm">
                      <div className="flex items-center justify-between">
                        <StatusTag tone="neutral">{ev.event_type}</StatusTag>
                        <span className="text-faint tabular-nums">{ev.timestamp}</span>
                      </div>
                      {ev.rule_name && <div className="mt-1 text-xs text-danger">{ev.rule_name}</div>}
                      <div className="mt-1.5 space-y-0.5 rounded bg-surface-muted px-2 py-1.5 text-xs">
                        {ev.exe && <div className="flex gap-2"><span className="w-12 shrink-0 text-faint">进程</span><span className="min-w-0 break-all font-mono text-ink">{ev.exe}</span></div>}
                        {ev.pid && <div className="flex gap-2"><span className="w-12 shrink-0 text-faint">PID</span><span className="font-mono text-ink">{ev.pid}</span></div>}
                        {ev.detail && <div className="flex gap-2"><span className="w-12 shrink-0 text-faint">详情</span><span className="min-w-0 break-all font-mono text-ink">{ev.detail}</span></div>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!resolving}
        title={t("detection.storylines.resolveTitle")}
        desc={resolving ? t("detection.storylines.resolveConfirmDesc", { id: resolving.story_id }) : undefined}
        loading={resolveMutation.isPending}
        onConfirm={() => resolving && resolveMutation.mutate(resolving.story_id)}
        onCancel={() => setResolving(null)}
      />
    </>
  );
}
