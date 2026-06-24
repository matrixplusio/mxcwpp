"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ArrowLeft, ListChecks, CheckCircle2, XCircle, Percent } from "lucide-react";
import { kubeApi } from "@/lib/api/kube";
import type { KubeBaselineResult, Severity } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Select } from "@/components/ui/Select";
import { Button } from "@/components/ui/Button";
import { Drawer } from "@/components/ui/Drawer";
import { StatusTag, SeverityTag } from "@/components/ui/Tag";
import { EmptyState } from "@/components/ui/EmptyState";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const isSeverity = (v: string): v is Severity => v === "critical" || v === "high" || v === "medium" || v === "low";
const resultTone = (r: string): Tone => (r === "pass" ? "success" : r === "fail" ? "danger" : "neutral");
const taskStatusTone = (s: string): Tone => (s === "done" ? "success" : s === "failed" ? "danger" : "info");
const fmtRate = (v: number | undefined) => `${Math.round(v == null ? 0 : v <= 1 ? v * 100 : v)}%`;
const resultLabelKey = (r: string) => `kube.baseline.result${r === "pass" ? "Pass" : r === "fail" ? "Fail" : "Error"}`;

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-faint">{label}</span>
      <span className="text-sm text-ink break-words whitespace-pre-wrap">{value}</span>
    </div>
  );
}

export default function BaselineTaskPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const [taskId, setTaskId] = useState(0);
  const [resultFilter, setResultFilter] = useState("");
  const [detail, setDetail] = useState<KubeBaselineResult | null>(null);

  useEffect(() => {
    const v = new URLSearchParams(window.location.search).get("id");
    setTaskId(v ? Number(v) : 0);
  }, []);

  const { data, isLoading } = useQuery({
    queryKey: ["kube-baseline-task", taskId, resultFilter],
    queryFn: () => kubeApi.getBaselineTaskDetail(taskId, { result: resultFilter || undefined }),
    enabled: taskId > 0,
  });
  const task = data?.task;

  const resultOptions = [
    { label: t("kube.baseline.allResult"), value: "" },
    { label: t("kube.baseline.resultPass"), value: "pass" },
    { label: t("kube.baseline.resultFail"), value: "fail" },
  ];

  const columns: Column<KubeBaselineResult>[] = [
    { key: "checkId", title: t("kube.common.colCheckId"), render: (r) => <span className="font-mono text-xs text-muted">{r.checkId}</span> },
    { key: "title", title: t("kube.baseline.colTitle"), render: (r) => <span className="block max-w-[320px] truncate text-ink">{r.title}</span> },
    { key: "category", title: t("kube.common.colCategory"), render: (r) => <span className="text-muted">{r.category}</span> },
    { key: "severity", title: t("common.level"), render: (r) => (isSeverity(r.severity) ? <SeverityTag level={r.severity} /> : <StatusTag tone="neutral">{r.severity}</StatusTag>) },
    { key: "result", title: t("kube.baseline.colResult"), render: (r) => <StatusTag tone={resultTone(r.result)}>{t(resultLabelKey(r.result))}</StatusTag> },
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
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => router.push("/kube/baseline")}
          className="inline-flex h-8 w-8 items-center justify-center rounded-control border border-border text-muted hover:text-ink"
          aria-label={t("common.back")}
        >
          <ArrowLeft size={16} />
        </button>
        <h1 className="text-lg font-semibold text-ink">{t("kube.baseline.taskDetailTitle")}</h1>
        {task && <StatusTag tone={taskStatusTone(task.status)}>{t(`kube.baseline.taskStatus.${task.status}`)}</StatusTag>}
        {task && <span className="font-medium text-ink">{task.clusterName}</span>}
        {task && <span className="text-xs text-faint tabular-nums">{task.startedAt}</span>}
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard compact label={t("kube.baseline.statTotalChecks")} value={task?.total ?? 0} icon={ListChecks} tone="default" />
        <StatCard compact label={t("kube.baseline.statPassed")} value={task?.passed ?? 0} icon={CheckCircle2} tone="success" />
        <StatCard compact label={t("kube.baseline.statFailed")} value={task?.failed ?? 0} icon={XCircle} tone="danger" />
        <StatCard compact label={t("kube.baseline.statPassRate")} value={fmtRate(task?.passRate)} icon={Percent} tone="success" />
      </div>

      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink">{t("kube.baseline.checklistTitle")}</h3>
        <Select value={resultFilter} onChange={setResultFilter} options={resultOptions} />
      </div>
      <Card>
        <DataTable
          columns={columns}
          rows={data?.items ?? []}
          rowKey={(r) => r.checkId ?? r.id}
          loading={isLoading}
          emptyText={t("kube.baseline.empty")}
          onRowClick={setDetail}
        />
      </Card>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title={t("kube.baseline.detailTitle")} width={600}>
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-base font-bold text-ink">{detail.title}</h2>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-faint">{detail.checkId}</span>
                {isSeverity(detail.severity) ? <SeverityTag level={detail.severity} /> : <StatusTag tone="neutral">{detail.severity}</StatusTag>}
                <StatusTag tone={resultTone(detail.result)}>{t(resultLabelKey(detail.result))}</StatusTag>
              </div>
            </div>

            {detail.description && <Field label={t("kube.baseline.fieldDescription")} value={detail.description} />}
            <Field label={t("kube.common.fieldCategory")} value={detail.category} />
            {detail.benchmark && <Field label={t("kube.baseline.fieldBenchmark")} value={detail.benchmark} />}

            {/* 不通过原因：受影响资源 */}
            {detail.result === "fail" && (
              <div className="space-y-2">
                <span className="text-xs uppercase tracking-wide text-faint">{t("kube.baseline.affectedTitle")}</span>
                {detail.affectedResources && detail.affectedResources.length > 0 ? (
                  <div className="rounded-card border border-border divide-y divide-border">
                    {detail.affectedResources.map((a, i) => (
                      <div key={i} className="flex items-center gap-2 px-3 py-2 text-sm">
                        <StatusTag tone="neutral">{a.kind}</StatusTag>
                        <span className="font-mono text-ink break-all">{a.name}</span>
                        {a.namespace && <span className="text-xs text-faint">ns: {a.namespace}</span>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted">{t("kube.baseline.affectedNone")}</p>
                )}
              </div>
            )}

            {detail.remediation && (
              <div className="rounded-card border border-border bg-surface-muted/50 p-3">
                <div className="mb-1 text-xs uppercase tracking-wide text-faint">{t("kube.baseline.fieldRemediation")}</div>
                <p className="text-sm text-ink whitespace-pre-wrap break-words">{detail.remediation}</p>
              </div>
            )}
          </div>
        )}
      </Drawer>

      {taskId > 0 && !task && !isLoading && <EmptyState title={t("kube.baseline.empty")} desc="" />}
    </div>
  );
}
