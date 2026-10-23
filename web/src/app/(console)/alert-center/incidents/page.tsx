"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { incidentsApi } from "@/lib/api/incidents";
import type { Alert, Incident, Severity, IncidentVerdict } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { HostCell } from "@/components/ui/HostCell";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { FilterBar } from "@/components/ui/FilterBar";
import { Select } from "@/components/ui/Select";
import { Drawer } from "@/components/ui/Drawer";
import { ResolveDialog } from "./_components/ResolveDialog";
import { IncidentTimeline } from "./_components/IncidentTimeline";
import { Button } from "@/components/ui/Button";
import { SeverityTag, StatusTag } from "@/components/ui/Tag";
import { toast } from "@/components/ui/toast";

const knownSeverities: Severity[] = ["critical", "high", "medium", "low"];
const isSeverity = (v: string): v is Severity => knownSeverities.includes(v as Severity);

// 从告警 actual(命中字段 JSON)提取具体证据:谁(进程/命令)动了谁(文件/IP)
function evidenceOf(actual: string | undefined): Array<{ k: string; v: string }> {
  if (!actual) return [];
  let o: Record<string, unknown>;
  try {
    o = JSON.parse(actual);
  } catch {
    return [];
  }
  const pick: Array<[string, string]> = [
    ["event_type", "事件"],
    ["exe", "进程"],
    ["cmdline", "命令行"],
    ["file_path", "文件"],
    ["remote_addr", "外联IP"],
    ["remote_port", "端口"],
    ["pid", "PID"],
    ["cwd", "工作目录"],
  ];
  const out: Array<{ k: string; v: string }> = [];
  for (const [key, label] of pick) {
    const val = o[key];
    if (val !== undefined && val !== null && String(val) !== "") out.push({ k: label, v: String(val) });
  }
  return out;
}

export default function IncidentsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [params, setParams] = useUrlState({ page: 1, page_size: 20, status: "active" });

  const statusOptions = [
    { label: t("alerts.incident.statusActive"), value: "active" },
    { label: t("alerts.incident.statusResolved"), value: "resolved" },
    { label: t("alerts.incident.statusAwaitingVerdict"), value: "awaiting_verdict" },
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
  // 自动关闭只说明主机上没有活跃告警了，结论仍要有人补。
  const awaitingVerdict = (r: Incident) =>
    r.status === "resolved" && r.resolved_by === "auto" && !r.verdict;
  const [detailId, setDetailId] = useState<string | null>(null);
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["incidents"] });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ["incident-detail", detailId],
    queryFn: () => incidentsApi.get(detailId!),
    enabled: !!detailId,
  });

  // 关闭必须带研判结论与原因——后端会拒绝缺任一项的请求。
  const resolveMutation = useMutation({
    mutationFn: (v: { id: string; verdict: IncidentVerdict; reason: string }) =>
      incidentsApi.resolve(v.id, v.verdict, v.reason),
    onSuccess: () => {
      invalidate();
      setResolving(null);
      toast.success(t("alerts.incident.resolved"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  // 认领是 MTTA 的终点，也是"这条有人在看"的唯一依据。
  const ackMutation = useMutation({
    mutationFn: (id: string) => incidentsApi.ack(id),
    onSuccess: () => {
      invalidate();
      queryClient.invalidateQueries({ queryKey: ["incident-timeline"] });
      queryClient.invalidateQueries({ queryKey: ["incident-detail"] });
      toast.success(t("alerts.incident.acked"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const commentMutation = useMutation({
    mutationFn: (v: { id: string; body: string; ref?: string }) =>
      incidentsApi.comment(v.id, v.body, v.ref),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["incident-timeline"] }),
    onError: (e: Error) => toast.error(e.message),
  });

  // 事件时间线：谁在什么时候基于什么做了什么，复盘唯一要看的东西。
  const { data: timeline } = useQuery({
    queryKey: ["incident-timeline", detailId],
    queryFn: () => incidentsApi.timeline(detailId!),
    enabled: !!detailId,
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
          <HostCell compact hostname={r.hostname} hostId={r.host_id} />
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
      // 战术列表是无空格的长串，不允许断行会把表撑宽
      render: (r) => <span className="block max-w-[14rem] font-mono text-xs [overflow-wrap:anywhere]">{r.tactic_count} 阶段 · {r.tactics || "—"}</span>,
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
        r.status === "resolved" && !awaitingVerdict(r) ? (
          <span className="text-faint">{t("alerts.incident.statusResolved")}</span>
        ) : (
          <button
            type="button"
            className="text-sm text-muted transition-colors hover:text-ink"
            onClick={() => setResolving(r)}
          >
            {t(awaitingVerdict(r) ? "alerts.incident.backfill" : "alerts.incident.resolve")}
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

      <Drawer
        open={!!detailId}
        onClose={() => setDetailId(null)}
        width={680}
        title={t("alerts.incident.detailTitle")}
        footer={
          detail && awaitingVerdict(detail.incident) ? (
            <Button
              onClick={() => {
                setResolving(detail.incident);
                setDetailId(null);
              }}
            >
              {t("alerts.incident.backfill")}
            </Button>
          ) : detail && detail.incident.status !== "resolved" ? (
            <div className="flex gap-2">
              {!detail.incident.acked_at && (
                <Button
                  variant="ghost"
                  disabled={ackMutation.isPending}
                  onClick={() => ackMutation.mutate(detail.incident.incident_id)}
                >
                  {t("alerts.incident.ack")}
                </Button>
              )}
              <Button
                onClick={() => {
                  setResolving(detail.incident);
                  setDetailId(null);
                }}
              >
                {t("alerts.incident.resolve")}
              </Button>
            </div>
          ) : undefined
        }
      >
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
                {detail.alerts.map((a) => {
                  const ev = evidenceOf(a.actual);
                  return (
                    <div key={a.id} className="rounded-md border border-line p-3 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-ink">{a.title || a.rule_id}</span>
                        <span className="text-faint tabular-nums">{a.first_seen_at}</span>
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-xs">
                        {isSeverity(a.severity) && <SeverityTag level={a.severity} />}
                        {a.category && <StatusTag tone="neutral">{a.category}</StatusTag>}
                      </div>
                      {ev.length > 0 && (
                        <div className="mt-2 space-y-0.5 rounded bg-surface-muted px-2 py-1.5">
                          {ev.map((e) => (
                            <div key={e.k} className="flex gap-2 text-xs">
                              <span className="w-14 shrink-0 text-faint">{e.k}</span>
                              <span className="min-w-0 break-all font-mono text-ink">{e.v}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 同期被抑制的命中：白名单或全舰队守卫压下的，研判时可能是关键线索 */}
            {detail.context_alerts && detail.context_alerts.length > 0 && (
              <SuppressedContext alerts={detail.context_alerts} />
            )}
          </div>
        ) : null}
        {detail && (
          <div className="mt-4 border-t border-line pt-4">
            <div className="mb-2 text-sm font-semibold text-ink">
              {t("alerts.incident.timeline")}
            </div>
            <IncidentTimeline
              events={timeline?.items ?? []}
              disabled={detail.incident.status === "resolved" && !awaitingVerdict(detail.incident)}
              submitting={commentMutation.isPending}
              onComment={(body, ref) =>
                commentMutation.mutate({ id: detail.incident.incident_id, body, ref })
              }
            />
          </div>
        )}
      </Drawer>

      <ResolveDialog
        open={!!resolving}
        title={resolving?.title}
        submitting={resolveMutation.isPending}
        backfill={!!resolving && awaitingVerdict(resolving)}
        onCancel={() => setResolving(null)}
        onSubmit={(verdict, reason) =>
          resolving && resolveMutation.mutate({ id: resolving.incident_id, verdict, reason })
        }
      />
    </>
  );
}

// SuppressedContext 同期被抑制的命中，默认收起：它们不属于事件本身，只在研判需要时展开参考。
function SuppressedContext({ alerts }: { alerts: Alert[] }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1 text-xs font-medium text-faint transition-colors hover:text-ink"
      >
        <ChevronRight size={14} className={`transition-transform ${open ? "rotate-90" : ""}`} />
        {t("alerts.incident.suppressedContext", { n: alerts.length })}
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          <p className="text-xs text-faint">{t("alerts.incident.suppressedContextHint")}</p>
          {alerts.map((a) => (
            <div key={a.id} className="flex items-center justify-between gap-3 rounded-md border border-line px-3 py-2 text-sm">
              <span className="min-w-0 truncate text-ink">{a.title || a.rule_id}</span>
              <span className="shrink-0 text-xs text-faint">
                {a.suppression_id
                  ? t("alerts.list.suppressedByRule", { id: a.suppression_id })
                  : t("alerts.incident.suppressedByFleetShort")}
                {" · "}
                <span className="tabular-nums">{a.last_seen_at}</span>
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
