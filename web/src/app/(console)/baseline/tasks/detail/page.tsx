"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ArrowLeft, ListChecks, CheckCircle2, XCircle, Percent } from "lucide-react";
import { baselineApi } from "@/lib/api/baseline";
import type { BaselineTask, BaselineTaskCheckItem, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { EmptyState } from "@/components/ui/EmptyState";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

const isSeverity = (v: string): v is Severity =>
  v === "critical" || v === "high" || v === "medium" || v === "low";
const resultTone = (r: string): Tone => (r === "pass" ? "success" : r === "fail" ? "danger" : "neutral");
const fmtRate = (v: number | undefined) => `${Math.round((v == null ? 0 : v) * 100)}%`;
const resultLabelKey = (r: string) =>
  `baseline.tasks.result${r === "pass" ? "Pass" : r === "fail" ? "Fail" : "Error"}`;

// 任务执行状态（注意：任务的"失败"是任务本身执行失败，与合规结果"不通过"区分）
const taskStatusMeta = (t: TFunction): Record<BaselineTask["status"], { label: string; tone: Tone }> => ({
  created: { label: t("baseline.tasks.statusCreated"), tone: "info" },
  pending: { label: t("baseline.tasks.statusPending"), tone: "info" },
  running: { label: t("baseline.tasks.statusRunning"), tone: "info" },
  completed: { label: t("baseline.tasks.statusCompleted"), tone: "success" },
  failed: { label: t("baseline.tasks.statusFailed"), tone: "danger" },
  cancelled: { label: t("baseline.tasks.statusCancelled"), tone: "neutral" },
});

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-faint">{label}</span>
      <span className="text-sm text-ink break-words whitespace-pre-wrap">{value}</span>
    </div>
  );
}

export default function BaselineTaskDetailPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const [taskId, setTaskId] = useState("");
  const [resultFilter, setResultFilter] = useState("");
  const [detail, setDetail] = useState<BaselineTaskCheckItem | null>(null);

  useEffect(() => {
    setTaskId(new URLSearchParams(window.location.search).get("id") ?? "");
  }, []);

  const { data, isLoading } = useQuery({
    queryKey: ["bl-task-checks", taskId, resultFilter],
    queryFn: () => baselineApi.getTaskChecks(taskId, { result: resultFilter || undefined }),
    enabled: !!taskId,
  });
  const task = data?.task;
  const statusMeta = task ? taskStatusMeta(t)[task.status] : null;

  const resultOptions = [
    { label: t("baseline.tasks.allResult"), value: "" },
    { label: t("baseline.tasks.resultPass"), value: "pass" },
    { label: t("baseline.tasks.resultFail"), value: "fail" },
  ];

  const columns: Column<BaselineTaskCheckItem>[] = [
    {
      key: "rule_id",
      title: t("baseline.tasks.colRuleId"),
      render: (r) => <span className="font-mono text-xs text-muted">{r.rule_id}</span>,
    },
    {
      key: "title",
      title: t("baseline.tasks.colCheckTitle"),
      render: (r) => <span className="block max-w-[320px] truncate text-ink">{r.title}</span>,
    },
    {
      key: "category",
      title: t("common.category"),
      render: (r) => <span className="text-muted">{r.category}</span>,
    },
    {
      key: "severity",
      title: t("common.level"),
      render: (r) =>
        isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>,
    },
    {
      key: "host_failed",
      title: t("baseline.tasks.colHostFailed"),
      align: "right",
      render: (r) => (
        <span className="tabular-nums text-muted">
          {r.host_failed}/{r.host_total}
        </span>
      ),
    },
    {
      key: "result",
      title: t("baseline.tasks.colResult"),
      render: (r) => <StatusTag tone={resultTone(r.result)}>{t(resultLabelKey(r.result))}</StatusTag>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <Button variant="ghost" className="h-8 px-3" onClick={(e) => { e.stopPropagation(); setDetail(r); }}>
          {t("common.details")}
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => router.push("/baseline/tasks")}
          className="inline-flex h-8 w-8 items-center justify-center rounded-control border border-border text-muted hover:text-ink"
          aria-label={t("common.back")}
        >
          <ArrowLeft size={16} />
        </button>
        <h1 className="text-lg font-semibold text-ink">{t("baseline.tasks.taskDetailTitle")}</h1>
        {statusMeta && <StatusTag tone={statusMeta.tone}>{statusMeta.label}</StatusTag>}
        {task && <span className="font-medium text-ink">{task.name || task.task_id}</span>}
        {task && <span className="text-xs text-faint tabular-nums">{task.created_at}</span>}
      </div>

      {/* 任务执行失败原因（任务本身失败，非合规不通过） */}
      {task?.status === "failed" && task.failed_reason && (
        <div className="rounded-card border border-danger/40 bg-danger/5 p-3 text-sm text-danger">
          {t("baseline.tasks.fieldFailedReason")}: {task.failed_reason}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard compact label={t("baseline.tasks.statTotalChecks")} value={data?.total ?? 0} icon={ListChecks} tone="default" />
        <StatCard compact label={t("baseline.tasks.statPassed")} value={data?.passed ?? 0} icon={CheckCircle2} tone="success" />
        <StatCard compact label={t("baseline.tasks.statFailed")} value={data?.failed ?? 0} icon={XCircle} tone="danger" />
        <StatCard compact label={t("baseline.tasks.statPassRate")} value={fmtRate(data?.pass_rate)} icon={Percent} tone="success" />
      </div>

      {/* 任务元信息 */}
      {task && (
        <Card>
          <div className="grid grid-cols-2 gap-x-6 gap-y-4 p-4 md:grid-cols-4">
            <Field label={t("baseline.tasks.fieldMatchedHost")} value={String(task.matched_host_count ?? 0)} />
            <Field label={t("baseline.tasks.fieldDispatchedHost")} value={String(task.dispatched_host_count ?? 0)} />
            <Field label={t("baseline.tasks.fieldCompletedHost")} value={String(task.completed_host_count ?? 0)} />
            <Field
              label={t("baseline.tasks.fieldPolicy")}
              value={task.policy_ids?.length ? task.policy_ids.join(", ") : task.policy_id || "—"}
            />
          </div>
        </Card>
      )}

      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink">{t("baseline.tasks.checklistTitle")}</h3>
        <Select value={resultFilter} onChange={setResultFilter} options={resultOptions} />
      </div>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.rule_id}
          loading={isLoading}
          emptyText={t("baseline.tasks.checklistEmpty")}
          onRowClick={setDetail}
        />
      </Card>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("baseline.tasks.checkDetailTitle")} width={600}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-base font-bold text-ink">{detail.title}</h2>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-faint">{detail.rule_id}</span>
                {isSeverity(detail.severity) ? <SeverityTag level={detail.severity} /> : <StatusTag tone="neutral">{detail.severity}</StatusTag>}
                <StatusTag tone={resultTone(detail.result)}>{t(resultLabelKey(detail.result))}</StatusTag>
              </div>
            </div>

            {detail.description && <Field label={t("baseline.tasks.fieldDescription")} value={detail.description} />}
            <Field label={t("common.category")} value={detail.category} />
            {detail.expected && <Field label={t("baseline.tasks.fieldBenchmark")} value={detail.expected} />}

            {/* 不通过原因：受影响主机 */}
            {detail.result === "fail" && (
              <div className="space-y-2">
                <span className="text-xs uppercase tracking-wide text-faint">{t("baseline.tasks.affectedTitle")}</span>
                {detail.affected_hosts && detail.affected_hosts.length > 0 ? (
                  <div className="rounded-card border border-border divide-y divide-border">
                    {detail.affected_hosts.map((a, i) => (
                      <div key={i} className="flex flex-col gap-1 px-3 py-2 text-sm">
                        <span className="font-mono text-ink break-all">{a.hostname || a.host_id}</span>
                        {a.actual && (
                          <span className="text-xs text-muted break-words">
                            {t("baseline.tasks.affectedActual")}: {a.actual}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted">{t("baseline.tasks.affectedNone")}</p>
                )}
              </div>
            )}

            {detail.remediation && (
              <div className="rounded-card border border-border bg-surface-muted/50 p-3">
                <div className="mb-1 text-xs uppercase tracking-wide text-faint">{t("baseline.tasks.fieldRemediation")}</div>
                <p className="text-sm text-ink whitespace-pre-wrap break-words">{detail.remediation}</p>
              </div>
            )}
          </div>
        )}
      </Drawer>

      {!!taskId && !task && !isLoading && <EmptyState title={t("baseline.tasks.checklistEmpty")} desc="" />}
    </div>
  );
}
