"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Server, GraduationCap, ShieldCheck, AlertTriangle } from "lucide-react";
import { detectionApi } from "@/lib/api/detection";
import type { BdeBaseline, BdeAlert } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { Pagination } from "@/components/ui/Pagination";
import { StatCard } from "@/components/ui/StatCard";
import { Tabs } from "@/components/ui/Tabs";
import { StatusTag } from "@/components/ui/Tag";
import { Drawer } from "@/components/ui/Drawer";

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

// 13 维行为指标释义：维度名 + 偏高时可能代表的威胁。让“产出”可读。
const METRIC_META: Record<string, { label: string; threat: string }> = {
  proc_exec_count: { label: "进程执行次数", threat: "突增=批量执行/脚本投递" },
  proc_unique_exe: { label: "唯一程序数", threat: "突增=运行了平时没有的程序/落地工具" },
  proc_fork_rate: { label: "进程派生速率", threat: "突增=fork 炸弹/蠕虫/批量扫描" },
  file_write_count: { label: "文件写入次数", threat: "突增=勒索加密/批量落盘" },
  file_unique_path: { label: "写入路径数", threat: "突增=跨目录大面积写入(勒索特征)" },
  file_sensitive_hits: { label: "敏感文件命中", threat: "触及 /etc/passwd、ssh key 等=凭证窃取/持久化" },
  net_connect_count: { label: "网络连接数", threat: "突增=横移/扫描/数据外传" },
  net_unique_ip: { label: "唯一对端 IP", threat: "突增=横向移动/批量外联" },
  net_unique_port: { label: "唯一端口数", threat: "突增=端口扫描" },
  net_external_ratio: { label: "外网连接占比", threat: "升高=异常外联/C2 回连" },
  dns_query_count: { label: "DNS 查询数", threat: "突增=DNS 隧道/信标" },
  dns_unique_domain: { label: "唯一域名数", threat: "突增=DGA 域名生成" },
  dns_nx_ratio: { label: "DNS 解析失败率", threat: "升高=DGA/DNS 隧道特征" },
};
const metricLabel = (key: string): string => METRIC_META[key]?.label ?? key;

// 由观测值/基线/z 生成人话解读
function interpretAlert(a: BdeAlert): { dir: string; tone: Tone; text: string } {
  const up = a.value >= a.mean;
  const z = Math.abs(a.z_score);
  const meta = METRIC_META[a.metric];
  const dir = up ? "↑ 高于基线" : "↓ 低于基线";
  const tone: Tone = z >= 4 ? "danger" : z >= 3 ? "warning" : "neutral";
  const threat = up && meta ? `，${meta.threat}` : "";
  const text = `${metricLabel(a.metric)} ${fmt(a.value)}（基线 ${fmt(a.mean)}，偏离 ${fmt(z)}σ）${threat}`;
  return { dir, tone, text };
}

const buildPhaseMeta = (t: TFunction): Record<BdeBaseline["phase"], { tone: Tone; label: string }> => ({
  learning: { tone: "warning", label: t("detection.bde.phaseLearning") },
  active: { tone: "success", label: t("detection.bde.phaseActive") },
});
const buildAlertStatusMeta = (t: TFunction): Record<BdeAlert["status"], { tone: Tone; label: string }> => ({
  open: { tone: "warning", label: t("detection.bde.alertStatusOpen") },
  resolved: { tone: "success", label: t("detection.bde.alertStatusResolved") },
  ignored: { tone: "neutral", label: t("detection.bde.alertStatusIgnored") },
});

function fmt(n: number): string {
  return Number.isInteger(n) ? String(n) : n.toFixed(2);
}

const buildStateColumns = (
  t: TFunction,
  phaseMeta: ReturnType<typeof buildPhaseMeta>,
  onProfile: (r: BdeBaseline) => void,
): Column<BdeBaseline>[] => [
  { key: "host_id", title: t("detection.bde.colHostId"), render: (r) => <span className="font-mono text-xs text-ink">{r.host_id}</span> },
  { key: "phase", title: t("detection.bde.colPhase"), render: (r) => <StatusTag tone={phaseMeta[r.phase].tone}>{phaseMeta[r.phase].label}</StatusTag> },
  {
    key: "progress",
    title: t("detection.bde.colProgress"),
    render: (r) => {
      const pct = Math.round(r.progress_pct ?? (r.phase === "active" ? 100 : 0));
      return (
        <div className="w-40">
          <div className="mb-1 flex justify-between text-xs">
            <span className="text-faint">
              {t("detection.bde.samplesShort")} {r.samples}/{r.required_min ?? 100}
            </span>
            <span className="tabular-nums text-muted">{pct}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-muted">
            <div
              className={r.phase === "active" ? "h-full bg-success" : "h-full bg-warning"}
              style={{ width: `${pct}%` }}
            />
          </div>
        </div>
      );
    },
  },
  {
    key: "blocking_reason",
    title: t("detection.bde.colStatusDetail"),
    render: (r) =>
      r.phase === "active" ? (
        <span className="text-xs text-success">{t("detection.bde.graduated")}</span>
      ) : (
        <div className="text-xs">
          <div className="text-muted">{r.blocking_reason || "—"}</div>
          {r.learning_ends && (
            <div className="text-faint">
              {t("detection.bde.learningEnds")}: {r.learning_ends}
            </div>
          )}
        </div>
      ),
  },
  { key: "first_seen", title: t("detection.bde.colFirstSeen"), render: (r) => <span className="tabular-nums text-faint">{r.first_seen}</span> },
  {
    key: "actions",
    title: t("common.actions"),
    align: "right",
    render: (r) => (
      <button
        type="button"
        className="text-sm text-muted transition-colors hover:text-ink disabled:opacity-40"
        disabled={!r.metrics?.length}
        onClick={() => onProfile(r)}
      >
        {t("detection.bde.viewProfile")}
      </button>
    ),
  },
];

const buildAlertColumns = (t: TFunction, alertStatusMeta: ReturnType<typeof buildAlertStatusMeta>): Column<BdeAlert>[] => [
  {
    key: "hostname",
    title: t("detection.bde.colHost"),
    render: (r) => (
      <div>
        <div className="font-medium text-ink">{r.hostname || r.host_id}</div>
        <div className="text-xs text-faint">{r.host_id}</div>
      </div>
    ),
  },
  { key: "metric", title: t("detection.bde.colMetric"), render: (r) => <span className="text-xs text-ink">{metricLabel(r.metric)}</span> },
  {
    key: "interpret",
    title: t("detection.bde.colInterpret"),
    render: (r) => {
      const it = interpretAlert(r);
      return (
        <div className="max-w-md">
          <StatusTag tone={it.tone}>{it.dir}</StatusTag>
          <div className="mt-1 text-xs text-muted">{it.text}</div>
        </div>
      );
    },
  },
  { key: "z_score", title: t("detection.bde.colZScore"), render: (r) => <span className="font-semibold tabular-nums text-ink">{fmt(r.z_score)}</span> },
  { key: "risk_score", title: t("detection.bde.colRiskScore"), render: (r) => <span className="tabular-nums text-ink">{fmt(r.risk_score)}</span> },
  {
    key: "status",
    title: t("common.status"),
    render: (r) => <StatusTag tone={alertStatusMeta[r.status].tone}>{alertStatusMeta[r.status].label}</StatusTag>,
  },
];

export default function BdePage() {
  const { t } = useTranslation();
  const phaseMeta = buildPhaseMeta(t);
  const alertStatusMeta = buildAlertStatusMeta(t);
  const tabs = [
    { key: "states", label: t("detection.bde.tabStates") },
    { key: "alerts", label: t("detection.bde.tabAlerts") },
  ];
  const [profileHost, setProfileHost] = useState<BdeBaseline | null>(null);
  const stateColumns = buildStateColumns(t, phaseMeta, setProfileHost);
  const alertColumns = buildAlertColumns(t, alertStatusMeta);
  const [tab, setTab] = useState("states");
  const [statePage, setStatePage] = useState(1);
  const [alertPage, setAlertPage] = useState(1);
  const pageSize = 20;

  const { data: stats } = useQuery({
    queryKey: ["bde-stats"],
    queryFn: () => detectionApi.bdeStats(),
  });

  const { data: states, isLoading: statesLoading } = useQuery({
    queryKey: ["bde-states", statePage],
    queryFn: () => detectionApi.listBdeStates({ page: statePage, page_size: pageSize }),
    enabled: tab === "states",
  });

  const { data: alerts, isLoading: alertsLoading } = useQuery({
    queryKey: ["bde-alerts", alertPage],
    queryFn: () => detectionApi.listBdeAlerts({ page: alertPage, page_size: pageSize }),
    enabled: tab === "alerts",
  });

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard compact label={t("detection.bde.statTotalHosts")} value={stats?.total_hosts ?? 0} icon={Server} tone="default" />
        <StatCard compact label={t("detection.bde.statLearning")} value={stats?.learning_hosts ?? 0} icon={GraduationCap} tone="warning" />
        <StatCard compact label={t("detection.bde.statActive")} value={stats?.active_hosts ?? 0} icon={ShieldCheck} tone="success" />
        <StatCard compact label={t("detection.bde.statOpenAlerts")} value={stats?.open_alerts ?? 0} icon={AlertTriangle} tone="danger" />
      </div>

      <Tabs items={tabs} active={tab} onChange={setTab} />

      {tab === "states" ? (
        <Card>
          <DataTable
            columns={stateColumns}
            rows={states?.items ?? []}
            rowKey={(r) => r.id}
            loading={statesLoading}
            emptyText={t("detection.bde.emptyStates")}
          />
          <Pagination page={statePage} pageSize={pageSize} total={states?.total ?? 0} onChange={setStatePage} />
        </Card>
      ) : (
        <Card>
          <DataTable
            columns={alertColumns}
            rows={alerts?.items ?? []}
            rowKey={(r) => r.id}
            loading={alertsLoading}
            emptyText={t("detection.bde.emptyAlerts")}
          />
          <Pagination page={alertPage} pageSize={pageSize} total={alerts?.total ?? 0} onChange={setAlertPage} />
        </Card>
      )}

      <Drawer
        open={!!profileHost}
        onClose={() => setProfileHost(null)}
        width={560}
        title={t("detection.bde.profileTitle")}
      >
        <p className="mb-3 text-xs text-faint">{t("detection.bde.profileDesc")}</p>
        <div className="space-y-1.5">
          {(profileHost?.metrics ?? []).map((m) => (
            <div key={m.key} className="flex items-center justify-between rounded-md border border-line px-3 py-2 text-sm">
              <div>
                <div className="text-ink">{metricLabel(m.key)}</div>
                <div className="text-xs text-faint">{METRIC_META[m.key]?.threat}</div>
              </div>
              <div className="text-right tabular-nums">
                <div className="text-ink">{fmt(m.mean)}</div>
                <div className="text-xs text-faint">±{fmt(m.stddev)}</div>
              </div>
            </div>
          ))}
        </div>
      </Drawer>
    </div>
  );
}
