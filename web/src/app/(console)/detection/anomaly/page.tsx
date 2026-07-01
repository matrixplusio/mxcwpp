"use client";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Activity, AlertTriangle, ShieldAlert } from "lucide-react";
import { useUrlState } from "@/hooks/useUrlState";
import { detectionApi } from "@/lib/api/detection";
import type { AnomalyEvent, Severity } from "@/lib/api/types";
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
import { CopyButton } from "@/components/ui/CopyButton";
import { toast } from "@/components/ui/toast";

interface ListParams {
  page: number;
  page_size: number;
  severity: string;
  status: string;
  alert_type: string;
  host_id: string;
}

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

// 13 维行为指标中文名(与 BDE 一致),让"主要指标"可读
const METRIC_LABEL: Record<string, string> = {
  proc_exec_count: "进程执行次数", proc_unique_exe: "唯一程序数", proc_fork_rate: "进程派生速率",
  file_write_count: "文件写入次数", file_unique_path: "写入路径数", file_sensitive_hits: "敏感文件命中",
  net_connect_count: "网络连接数", net_unique_ip: "唯一对端IP", net_unique_port: "唯一端口数", net_external_ratio: "外网连接占比",
  dns_query_count: "DNS查询数", dns_unique_domain: "唯一域名数", dns_nx_ratio: "DNS解析失败率",
};
const metricCn = (k: string) => METRIC_LABEL[k] ?? k;

// 异常模式 → 人话研判 + 处置建议
const PATTERN_VERDICT: Record<string, { verdict: string; action: string }> = {
  c2_beacon: { verdict: "主机疑似 C2 回连:网络+DNS 活动异常升高,符合信标/隐蔽通道特征。", action: "隔离主机,核对外联进程链是否合法,封禁可疑外联 IP/域名。" },
  data_exfiltration: { verdict: "疑似数据外传:外联与数据传输量异常,可能存在数据渗出。", action: "阻断外传通道,排查敏感数据访问,评估泄露范围。" },
  privilege_escalation: { verdict: "疑似提权:进程/权限相关指标异常,可能存在提权尝试。", action: "核查 sudo/setuid 与内核提权痕迹,修补相关漏洞。" },
  reconnaissance: { verdict: "疑似侦察:短时大量探测类行为,可能是攻击前置侦察。", action: "确认是否来自合法运维,核查来源进程。" },
};

// 由异常上下文生成升高指标列表 [{name,current,baseline,ratio}]
function elevatedMetrics(ctx: unknown): Array<{ name: string; current: number; baseline: number; ratio: number }> {
  if (!ctx || typeof ctx !== "object") return [];
  const em = (ctx as Record<string, unknown>).elevated_metrics;
  if (!Array.isArray(em)) return [];
  return em
    .map((m) => {
      const o = m as Record<string, unknown>;
      return { name: String(o.name ?? ""), current: Number(o.current ?? 0), baseline: Number(o.baseline ?? 0), ratio: Number(o.ratio ?? 0) };
    })
    .filter((m) => m.name)
    .sort((a, b) => b.ratio - a.ratio);
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const buildAlertTypeLabels = (t: TFunction): Record<AnomalyEvent["alert_type"], string> => ({
  isolation_forest: t("detection.anomaly.typeIsolationForest"),
  correlation: t("detection.anomaly.typeCorrelation"),
});
const buildStatusMeta = (t: TFunction): Record<AnomalyEvent["status"], { tone: Tone; label: string }> => ({
  open: { tone: "warning", label: t("detection.anomaly.statusOpen") },
  confirmed: { tone: "danger", label: t("detection.anomaly.statusConfirmed") },
  false_positive: { tone: "neutral", label: t("detection.anomaly.statusFalsePositive") },
});

const buildSeverityOptions = (t: TFunction) => [
  { label: t("common.allSeverity"), value: "" },
  ...SEVERITIES.map((s) => ({ label: t(`common.severity.${s}`), value: s })),
];
const buildStatusOptions = (t: TFunction) => [
  { label: t("common.allStatus"), value: "" },
  { label: t("detection.anomaly.statusOpen"), value: "open" },
  { label: t("detection.anomaly.statusConfirmed"), value: "confirmed" },
  { label: t("detection.anomaly.statusFalsePositive"), value: "false_positive" },
];
const buildAlertTypeOptions = (t: TFunction) => [
  { label: t("common.allType"), value: "" },
  { label: t("detection.anomaly.typeIsolationForest"), value: "isolation_forest" },
  { label: t("detection.anomaly.typeCorrelation"), value: "correlation" },
];

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 text-sm">
      <span className="w-20 shrink-0 text-muted">{label}</span>
      <span className="break-all text-ink">{value}</span>
    </div>
  );
}

export default function AnomalyPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const alertTypeLabels = buildAlertTypeLabels(t);
  const statusMeta = buildStatusMeta(t);
  const severityOptions = buildSeverityOptions(t);
  const statusOptions = buildStatusOptions(t);
  const alertTypeOptions = buildAlertTypeOptions(t);
  const [params, setParams] = useUrlState({
    page: 1,
    page_size: 20,
    severity: "",
    status: "",
    alert_type: "",
    host_id: "",
  });

  const { data: stats } = useQuery({
    queryKey: ["anomaly-stats"],
    queryFn: () => detectionApi.anomalyStats(),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["anomalies", params],
    queryFn: () =>
      detectionApi.listAnomalies({
        page: params.page,
        page_size: params.page_size,
        severity: params.severity || undefined,
        status: params.status || undefined,
        alert_type: params.alert_type || undefined,
        host_id: params.host_id || undefined,
      }),
  });

  const [detail, setDetail] = useState<AnomalyEvent | null>(null);
  const [confirming, setConfirming] = useState<AnomalyEvent | null>(null);
  const [markingFp, setMarkingFp] = useState<AnomalyEvent | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["anomalies"] });
    queryClient.invalidateQueries({ queryKey: ["anomaly-stats"] });
  };

  const resolveMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: "confirmed" | "false_positive" }) =>
      detectionApi.resolveAnomaly(id, status),
    onSuccess: (_data, vars) => {
      invalidate();
      setConfirming(null);
      setMarkingFp(null);
      setDetail(null);
      toast.success(vars.status === "confirmed" ? t("detection.anomaly.confirmed") : t("detection.anomaly.markedFp"));
    },
    onError: (e: Error) => toast.error(e.message),
  });

  const renderContext = (ctx: AnomalyEvent["trigger_context"]) => {
    if (ctx === undefined || ctx === null) return "—";
    if (typeof ctx === "string") return ctx;
    return JSON.stringify(ctx, null, 2);
  };

  const columns: Column<AnomalyEvent>[] = [
    {
      key: "hostname",
      title: t("detection.anomaly.colHost"),
      render: (r) => (
        <div>
          <div className="font-medium text-ink">{r.hostname || r.host_id}</div>
          <div className="text-xs text-faint">{r.host_id}</div>
        </div>
      ),
    },
    {
      key: "alert_type",
      title: t("detection.anomaly.colType"),
      render: (r) => <StatusTag tone="neutral">{alertTypeLabels[r.alert_type] ?? r.alert_type}</StatusTag>,
    },
    { key: "severity", title: t("common.level"), render: (r) => <SeverityTag level={r.severity} /> },
    {
      key: "anomaly_score",
      title: t("detection.anomaly.colAnomalyScore"),
      render: (r) => <span className="font-semibold tabular-nums text-ink">{r.anomaly_score.toFixed(2)}</span>,
    },
    {
      key: "top_metric",
      title: t("detection.anomaly.colTopMetric"),
      render: (r) => <span className="font-mono text-xs text-faint">{r.top_metric || "—"}</span>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={statusMeta[r.status].tone}>{statusMeta[r.status].label}</StatusTag>,
    },
    {
      key: "actions",
      title: t("common.actions"),
      align: "right",
      render: (r) => (
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <button type="button" className="text-sm text-muted transition-colors hover:text-ink" onClick={() => setDetail(r)}>
            {t("common.details")}
          </button>
          {r.status === "open" && (
            <>
              <button type="button" className="text-sm text-danger transition-colors hover:opacity-80" onClick={() => setConfirming(r)}>
                {t("detection.anomaly.actionConfirm")}
              </button>
              <button type="button" className="text-sm text-muted transition-colors hover:text-ink" onClick={() => setMarkingFp(r)}>
                {t("detection.anomaly.actionFalsePositive")}
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <>
      <div className="mb-5 grid grid-cols-2 gap-3 md:grid-cols-3">
        <StatCard compact label={t("detection.anomaly.statTotal")} value={stats?.total ?? 0} icon={Activity} tone="default" />
        <StatCard compact label={t("detection.anomaly.statOpen")} value={stats?.open ?? 0} icon={AlertTriangle} tone="warning" />
        <StatCard compact label={t("detection.anomaly.statCritical")} value={stats?.critical ?? 0} icon={ShieldAlert} tone="danger" />
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
          <Select
            value={params.alert_type}
            onChange={(v) => setParams((p) => ({ ...p, alert_type: v, page: 1 }))}
            options={alertTypeOptions}
          />
          <Input
            value={params.host_id}
            onChange={(e) => setParams((p) => ({ ...p, host_id: e.target.value, page: 1 }))}
            placeholder={t("detection.anomaly.filterHostId")}
            className="w-56"
          />
        </FilterBar>
        <Card>
          <DataTable
            columns={columns}
            rows={data?.items ?? []}
            rowKey={(r) => r.id}
            loading={isLoading}
            emptyText={t("detection.anomaly.empty")}
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
        title={t("detection.anomaly.detailTitle")}
        width={560}
        footer={
          detail?.status === "open" ? (
            <>
              <Button variant="ghost" onClick={() => detail && setMarkingFp(detail)}>
                {t("detection.anomaly.actionFalsePositive")}
              </Button>
              <Button onClick={() => detail && setConfirming(detail)}>{t("detection.anomaly.actionConfirm")}</Button>
            </>
          ) : undefined
        }
      >
        {detail && (
          <div className="space-y-5">
            <div className="space-y-2">
              <h2 className="text-lg font-bold text-ink">{detail.hostname || detail.host_id}</h2>
              <div className="flex items-center gap-2">
                <SeverityTag level={detail.severity} />
                <StatusTag tone="neutral">{alertTypeLabels[detail.alert_type] ?? detail.alert_type}</StatusTag>
                <StatusTag tone={statusMeta[detail.status].tone}>{statusMeta[detail.status].label}</StatusTag>
              </div>
            </div>
            <div className="space-y-2">
              <Field label={t("detection.anomaly.fieldHostId")} value={<span className="inline-flex items-center gap-1.5">{detail.host_id}<CopyButton text={detail.host_id} /></span>} />
              <Field label={t("detection.anomaly.fieldPattern")} value={detail.pattern_name || "—"} />
              <Field label={t("detection.anomaly.fieldAnomalyScore")} value={<span className="tabular-nums">{detail.anomaly_score.toFixed(2)}</span>} />
              <Field label={t("detection.anomaly.fieldTopMetric")} value={<span className="font-mono">{detail.top_metric || "—"}</span>} />
              <Field label={t("detection.anomaly.fieldTopValue")} value={<span className="tabular-nums">{detail.top_value}</span>} />
              <Field label={t("detection.anomaly.fieldFoundAt")} value={<span className="tabular-nums">{detail.created_at}</span>} />
            </div>
            {/* 研判与处置(人话,取代直接看元数据) */}
            {(() => {
              const v = PATTERN_VERDICT[detail.pattern_name ?? ""];
              const elevated = elevatedMetrics(detail.trigger_context);
              const verdict = v?.verdict
                ?? (elevated.length > 0
                  ? `检测到异常行为:${elevated.slice(0, 3).map((m) => `${metricCn(m.name)}升至基线 ${m.ratio.toFixed(1)} 倍`).join("、")}。`
                  : detail.description || "检测到偏离基线的异常行为。");
              const action = v?.action ?? "核查该主机近期进程/网络/文件行为是否为合法运维。";
              return (
                <div className="rounded-md border border-line bg-surface-muted p-4">
                  <div className="mb-1.5 text-sm font-semibold text-ink">{t("detection.anomaly.verdict")}</div>
                  <p className="text-sm leading-relaxed text-ink">{verdict}</p>
                  <div className="mt-3 mb-1 text-sm font-semibold text-ink">{t("detection.anomaly.recommendation")}</div>
                  <p className="text-sm leading-relaxed text-muted">{action}</p>
                </div>
              );
            })()}

            {/* 升高指标(中文+倍数) */}
            {elevatedMetrics(detail.trigger_context).length > 0 && (
              <div>
                <div className="mb-1.5 text-sm font-medium text-ink">{t("detection.anomaly.elevatedMetrics")}</div>
                <div className="space-y-1.5">
                  {elevatedMetrics(detail.trigger_context).slice(0, 8).map((m) => (
                    <div key={m.name} className="flex items-center justify-between rounded-md border border-line px-3 py-1.5 text-sm">
                      <span className="text-ink">{metricCn(m.name)}</span>
                      <span className="tabular-nums text-muted">
                        {m.current} <span className="text-faint">(基线 {m.baseline.toFixed(2)})</span>{" "}
                        <span className="font-semibold text-danger">×{m.ratio.toFixed(1)}</span>
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 原始上下文折叠(给深度排查) */}
            <details>
              <summary className="cursor-pointer text-sm font-medium text-muted hover:text-ink">{t("detection.anomaly.triggerContext")}</summary>
              <pre className="mt-2 overflow-x-auto rounded-control bg-surface-muted p-3 font-mono text-xs text-ink whitespace-pre-wrap break-all">
                {renderContext(detail.trigger_context)}
              </pre>
            </details>
          </div>
        )}
      </Drawer>

      <ConfirmDialog
        open={!!confirming}
        title={t("detection.anomaly.confirmTitle")}
        desc={confirming ? t("detection.anomaly.confirmDesc", { host: confirming.hostname || confirming.host_id }) : undefined}
        loading={resolveMutation.isPending}
        onConfirm={() => confirming && resolveMutation.mutate({ id: confirming.id, status: "confirmed" })}
        onCancel={() => setConfirming(null)}
      />
      <ConfirmDialog
        open={!!markingFp}
        title={t("detection.anomaly.fpTitle")}
        desc={markingFp ? t("detection.anomaly.fpDesc", { host: markingFp.hostname || markingFp.host_id }) : undefined}
        loading={resolveMutation.isPending}
        onConfirm={() => markingFp && resolveMutation.mutate({ id: markingFp.id, status: "false_positive" })}
        onCancel={() => setMarkingFp(null)}
      />
    </>
  );
}
