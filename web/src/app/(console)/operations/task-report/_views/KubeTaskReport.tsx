"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Bell, ShieldOff, CheckCircle2, AlertTriangle } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { DateRange } from "@/lib/api/reports";
import type { KubeExecutiveReport } from "@/lib/api/types";
import { ExecutiveReport } from "../_components/ExecutiveReport";
import { SavedReportsList } from "../_components/SavedReportsList";
import { DataTable } from "@/components/ui/DataTable";
import type { Column } from "@/components/ui/DataTable";
import { StatCard } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { StatusTag } from "@/components/ui/Tag";
import { Tabs } from "@/components/ui/Tabs";
import { RangePicker, lastNDays } from "@/components/ui/RangePicker";

// ─── Section sub-components ───────────────────────────────────────────────────

function AlarmStatisticsContent({ d }: { d: KubeExecutiveReport }) {
  const { t } = useTranslation();
  const s = d.alarmStatistics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCard
          label={t("operations.taskReport.kube.totalAlarms")}
          value={s.totalAlarms}
          icon={Bell}
          compact
        />
        <StatCard
          label={t("operations.taskReport.kube.pendingAlarms")}
          value={s.pendingAlarms}
          icon={AlertTriangle}
          tone="danger"
          compact
        />
        <StatCard
          label={t("operations.taskReport.kube.processedAlarms")}
          value={s.processedAlarms}
          icon={CheckCircle2}
          tone="success"
          compact
        />
        <StatCard
          label={t("operations.taskReport.kube.ignoredAlarms")}
          value={s.ignoredAlarms}
          icon={ShieldOff}
          compact
        />
      </div>
      {Object.keys(s.bySeverity).length > 0 && (
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-wide text-faint">
            {t("operations.taskReport.distSeverity")}
          </p>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm md:grid-cols-4">
            {Object.entries(s.bySeverity).map(([sev, cnt]) => (
              <div
                key={sev}
                className="flex justify-between border-b border-border/40 py-1"
              >
                <span className="capitalize text-muted">
                  {t(`common.severity.${sev}`, { defaultValue: sev })}
                </span>
                <span className="tabular-nums text-ink">{cnt}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {Object.keys(s.byAlarmType).length > 0 && (
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-wide text-faint">
            {t("operations.taskReport.kube.alarmTypeLabel")}
          </p>
          <div className="space-y-1.5">
            {Object.entries(s.byAlarmType).map(([type, cnt]) => {
              const total = Object.values(s.byAlarmType).reduce(
                (a, b) => a + b,
                0,
              );
              const pct =
                total > 0 ? Math.round(((cnt as number) / total) * 100) : 0;
              return (
                <div key={type} className="space-y-1">
                  <div className="flex justify-between text-xs text-muted">
                    <span>{type}</span>
                    <span>
                      {cnt as number} ({pct}%)
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-surface-muted">
                    <div
                      className="h-1.5 rounded-full bg-danger transition-all"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function BaselineContent({ d }: { d: KubeExecutiveReport }) {
  const { t } = useTranslation();
  const s = d.baselineStatistics;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <StatCard
          label={t("operations.taskReport.kube.passed")}
          value={s.passed}
          icon={CheckCircle2}
          tone="success"
          compact
        />
        <StatCard
          label={t("operations.taskReport.kube.failed")}
          value={s.failed}
          icon={ShieldOff}
          tone="danger"
          compact
        />
        <StatCard
          label={t("operations.taskReport.kube.warning")}
          value={s.warning}
          icon={AlertTriangle}
          tone="warning"
          compact
        />
      </div>

      {d.baselineRiskItems && d.baselineRiskItems.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-faint">
            {t("operations.taskReport.kube.riskItems")}
          </p>
          <div className="space-y-2">
            {d.baselineRiskItems.slice(0, 10).map((item) => (
              <div
                key={`${item.checkId}-${item.clusterName}`}
                className="rounded-control border border-border/60 bg-surface p-3 text-sm"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="font-medium text-ink">
                    [{item.checkId}] {item.description}
                  </span>
                  <StatusTag
                    tone={
                      item.severity === "critical"
                        ? "danger"
                        : item.severity === "high"
                          ? "warning"
                          : "neutral"
                    }
                  >
                    {item.severityLabel || item.severity}
                  </StatusTag>
                </div>
                <div className="mt-1 text-xs text-faint">
                  {t("operations.taskReport.kube.clusterName")}:{" "}
                  {item.clusterName} ·{" "}
                  {t("operations.taskReport.kube.category")}: {item.category}
                </div>
                {item.remediation && (
                  <p className="mt-1 text-xs text-muted">{item.remediation}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {d.failedCheckDetails && d.failedCheckDetails.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-faint">
            {t("operations.taskReport.kube.failedChecks")}
          </p>
          <FailedCheckTable d={d} />
        </div>
      )}
    </div>
  );
}

function FailedCheckTable({ d }: { d: KubeExecutiveReport }) {
  const { t } = useTranslation();
  type Row = KubeExecutiveReport["failedCheckDetails"][number];
  const columns: Column<Row>[] = [
    {
      key: "checkId",
      title: t("operations.taskReport.kube.checkId"),
      render: (r) => <span className="font-mono text-xs">{r.checkId}</span>,
    },
    {
      key: "checkName",
      title: t("operations.taskReport.kube.checkName"),
      render: (r) => <span className="text-ink">{r.checkName}</span>,
    },
    {
      key: "severity",
      title: t("operations.taskReport.kube.severity"),
      render: (r) => (
        <StatusTag
          tone={
            r.severity === "critical"
              ? "danger"
              : r.severity === "high"
                ? "warning"
                : "neutral"
          }
        >
          {r.severityLabel || r.severity}
        </StatusTag>
      ),
    },
    {
      key: "clusterName",
      title: t("operations.taskReport.kube.clusterName"),
      render: (r) => r.clusterName || "-",
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.failedCheckDetails}
      rowKey={(r) => `${r.checkId}-${r.clusterName}`}
    />
  );
}

function ClusterDetailsContent({ d }: { d: KubeExecutiveReport }) {
  const { t } = useTranslation();
  type Row = KubeExecutiveReport["clusterDetails"][number];
  const columns: Column<Row>[] = [
    {
      key: "clusterName",
      title: t("operations.taskReport.kube.clusterName"),
      render: (r) => (
        <span className="font-medium text-ink">{r.clusterName}</span>
      ),
    },
    {
      key: "alarmCount",
      title: t("operations.taskReport.kube.alarmCount"),
      align: "right",
      render: (r) => r.alarmCount,
    },
    {
      key: "baselinePassRate",
      title: t("operations.taskReport.kube.baselinePassRate"),
      align: "right",
      render: (r) => `${r.baselinePassRate.toFixed(1)}%`,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.clusterDetails}
      rowKey={(r) => r.clusterName}
    />
  );
}

function TopAlarmsContent({ d }: { d: KubeExecutiveReport }) {
  const { t } = useTranslation();
  type Row = KubeExecutiveReport["topAlarms"][number];
  const columns: Column<Row>[] = [
    {
      key: "namespace",
      title: t("operations.taskReport.kube.namespace"),
      render: (r) => r.namespace || "-",
    },
    {
      key: "target",
      title: t("operations.taskReport.kube.target"),
      render: (r) => r.target || "-",
    },
    {
      key: "alarmType",
      title: t("operations.taskReport.kube.alarmType"),
      render: (r) => r.alarmType || "-",
    },
    {
      key: "count",
      title: t("operations.taskReport.kube.count"),
      align: "right",
      render: (r) => r.count,
    },
  ];
  return (
    <DataTable
      columns={columns}
      rows={d.topAlarms}
      rowKey={(r) =>
        `${r.namespace}-${r.target}-${r.alarmType}-${r.count}`
      }
    />
  );
}

// ─── Detail renderer (shared by generate and saved paths) ─────────────────────

function KubeDetailView({
  d,
  range,
  onBack,
}: {
  d: KubeExecutiveReport;
  range?: DateRange;
  onBack: () => void;
}) {
  const { t } = useTranslation();
  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    if (!range) return;
    setExporting(true);
    try {
      await reportsApi.downloadPdf(
        "/reports/kube/pdf",
        { start_time: range.start, end_time: range.end },
        "kube-report.pdf",
      );
    } finally {
      setExporting(false);
    }
  }

  return (
    <ExecutiveReport
      meta={{
        title: d.meta.reportTitle,
        subtitleEn: "Container Security Report",
        infoRows: [
          {
            label: t("operations.taskReport.kube.infoReportId"),
            value: d.meta.reportId,
          },
          {
            label: t("operations.taskReport.kube.infoGeneratedAt"),
            value: d.meta.generatedAt,
          },
          {
            label: t("operations.taskReport.kube.infoReportPeriod"),
            value: d.meta.reportPeriod,
          },
          {
            label: t("operations.taskReport.kube.infoCheckTarget"),
            value: d.meta.checkTarget,
          },
        ],
        company: d.meta.companyName || undefined,
      }}
      banner={{
        tone: d.summary.hasCriticalAlarm ? "danger" : "success",
        text: d.summary.overallConclusion || d.summary.alarmOverview,
      }}
      sections={[
        {
          title: t("operations.taskReport.kube.secAlarms"),
          content: <AlarmStatisticsContent d={d} />,
        },
        {
          title: t("operations.taskReport.kube.secBaseline"),
          content: <BaselineContent d={d} />,
        },
        {
          title: t("operations.taskReport.kube.secClusters"),
          content:
            d.clusterDetails && d.clusterDetails.length > 0 ? (
              <ClusterDetailsContent d={d} />
            ) : null,
        },
        {
          title: t("operations.taskReport.kube.secTopAlarms"),
          content:
            d.topAlarms && d.topAlarms.length > 0 ? (
              <TopAlarmsContent d={d} />
            ) : null,
        },
      ]}
      recommendation={
        d.recommendation
          ? {
              assessment: d.recommendation.overallAssessment,
              suggestions: d.recommendation.actionSuggestions ?? [],
              disclaimer: d.recommendation.disclaimer || undefined,
            }
          : undefined
      }
      onBack={onBack}
      onExportPdf={range ? handleExport : undefined}
      exporting={exporting}
    />
  );
}

// ─── Generate sub-tab ─────────────────────────────────────────────────────────

function GenerateTab() {
  const { t } = useTranslation();
  const [range, setRange] = useState<DateRange>(lastNDays(30));
  const [queriedRange, setQueriedRange] = useState<DateRange | null>(null);

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ["kube-executive", queriedRange],
    queryFn: () => reportsApi.kubeExecutive(queriedRange!),
    enabled: !!queriedRange,
  });

  if (queriedRange && data) {
    return (
      <KubeDetailView
        d={data}
        range={queriedRange}
        onBack={() => setQueriedRange(null)}
      />
    );
  }

  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center gap-3">
        <RangePicker value={range} onChange={setRange} />
        <Button
          variant="primary"
          onClick={() => setQueriedRange({ ...range })}
          disabled={isFetching}
        >
          {isFetching
            ? t("operations.taskReport.loading")
            : t("operations.taskReport.kube.generateBtn")}
        </Button>
      </div>
      {isError && (
        <p className="mt-4 text-sm text-danger">
          {(error as Error)?.message ?? t("operations.taskReport.emptyData")}
        </p>
      )}
    </Card>
  );
}

// ─── Saved Reports sub-tab ────────────────────────────────────────────────────

function SavedTab() {
  const { t } = useTranslation();
  const [viewingId, setViewingId] = useState<number | null>(null);

  const { data: savedDetail, isLoading } = useQuery({
    queryKey: ["saved-report-detail", viewingId],
    queryFn: () => reportsApi.getGenerated(viewingId!),
    enabled: !!viewingId,
  });

  if (viewingId) {
    if (isLoading || !savedDetail) {
      return (
        <Card className="p-10 text-center text-muted">
          {t("operations.taskReport.kube.loadingDetail")}
        </Card>
      );
    }
    const d = savedDetail as unknown as KubeExecutiveReport;
    return <KubeDetailView d={d} onBack={() => setViewingId(null)} />;
  }

  return <SavedReportsList type="kube" onView={(id) => setViewingId(id)} />;
}

// ─── Main component ───────────────────────────────────────────────────────────

type SubTab = "generate" | "saved";

export function KubeTaskReport() {
  const { t } = useTranslation();
  const [subTab, setSubTab] = useState<SubTab>("generate");

  const subTabItems = [
    {
      key: "generate",
      label: t("operations.taskReport.kube.subTabGenerate"),
    },
    {
      key: "saved",
      label: t("operations.taskReport.kube.subTabSavedReports"),
    },
  ];

  return (
    <div className="space-y-4">
      <Tabs
        items={subTabItems}
        active={subTab}
        onChange={(key) => setSubTab(key as SubTab)}
      />
      <div>{subTab === "generate" ? <GenerateTab /> : <SavedTab />}</div>
    </div>
  );
}
