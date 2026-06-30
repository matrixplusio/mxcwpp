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

type Tone = "success" | "warning" | "danger" | "info" | "neutral";

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

const buildStateColumns = (t: TFunction, phaseMeta: ReturnType<typeof buildPhaseMeta>): Column<BdeBaseline>[] => [
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
  { key: "metric", title: t("detection.bde.colMetric"), render: (r) => <span className="font-mono text-xs text-faint">{r.metric}</span> },
  { key: "value", title: t("detection.bde.colValue"), render: (r) => <span className="tabular-nums text-ink">{fmt(r.value)}</span> },
  { key: "mean", title: t("detection.bde.colMean"), render: (r) => <span className="tabular-nums text-muted">{fmt(r.mean)}</span> },
  { key: "stddev", title: t("detection.bde.colStddev"), render: (r) => <span className="tabular-nums text-muted">{fmt(r.stddev)}</span> },
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
  const stateColumns = buildStateColumns(t, phaseMeta);
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
    </div>
  );
}
