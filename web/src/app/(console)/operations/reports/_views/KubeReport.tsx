"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { AlertTriangle, CheckCircle2, Download, MinusCircle, Network, Server, ShieldCheck, XCircle } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { DateRange } from "@/lib/api/reports";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { ChartCard } from "@/components/ui/ChartCard";
import { DataTable } from "@/components/ui/DataTable";
import { EmptyState } from "@/components/ui/EmptyState";
import { StatCard } from "@/components/ui/StatCard";
import { SeverityTag } from "@/components/ui/Tag";
import type { Column } from "@/components/ui/DataTable";
import type { Severity } from "@/lib/api/types";

interface Props {
  range: DateRange;
}

const SEV_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#FBBF24",
  low: "#94A3B8",
};

export function KubeReport({ range }: Props) {
  const { t } = useTranslation();

  const SEV_LABEL: Record<string, string> = {
    critical: t("common.severity.critical"),
    high: t("common.severity.high"),
    medium: t("common.severity.medium"),
    low: t("common.severity.low"),
  };

  const { data, isLoading } = useQuery({
    queryKey: ["reports-kube", range.start, range.end],
    queryFn: () => reportsApi.kubeModule(range),
  });

  function handleExportPdf() {
    void reportsApi.downloadPdf(
      "/reports/kube/pdf",
      { start_time: range.start, end_time: range.end },
      "kube-report.pdf",
    );
  }

  if (isLoading && !data) {
    return <Card className="p-10 text-center text-muted">{t("operations.reports.loading")}</Card>;
  }

  if (!data) {
    return <EmptyState title={t("operations.reports.emptyData")} desc="" />;
  }

  const {
    summary,
    severityDistribution,
    alarmTypeDistribution,
    topNamespaces,
    topTargets,
    baselineOverview,
    baselineAlerts,
    baselineBySeverity,
    baselineByCategory,
  } = data;

  // --- Chart options ---

  const baselineSevEntries = Object.entries(baselineBySeverity ?? {}).filter(([, v]) => v > 0);
  const baselineSeverityOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [
      {
        type: "pie",
        radius: ["40%", "70%"],
        data: baselineSevEntries.map(([name, value]) => ({
          name: SEV_LABEL[name] ?? name,
          value,
          itemStyle: { color: SEV_COLORS[name] },
        })),
      },
    ],
  };

  const baselineCatEntries = Object.entries(baselineByCategory ?? {}).filter(([, v]) => v > 0);
  const baselineCategoryOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: "3%", right: "8%", bottom: "3%", containLabel: true },
    xAxis: { type: "value" },
    yAxis: {
      type: "category",
      data: baselineCatEntries.map(([k]) => k),
    },
    series: [
      {
        type: "bar",
        data: baselineCatEntries.map(([, v]) => ({
          value: v,
          itemStyle: { color: "#EF4444" },
        })),
      },
    ],
  };

  const alarmSevEntries = Object.entries(severityDistribution ?? {}).filter(([, v]) => v > 0);
  const alarmSeverityOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [
      {
        type: "pie",
        radius: ["40%", "70%"],
        data: alarmSevEntries.map(([name, value]) => ({
          name: SEV_LABEL[name] ?? name,
          value,
          itemStyle: { color: SEV_COLORS[name] },
        })),
      },
    ],
  };

  const alarmTypeEntries = Object.entries(alarmTypeDistribution ?? {}).filter(([, v]) => v > 0);
  const alarmTypeOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
    xAxis: {
      type: "category",
      data: alarmTypeEntries.map(([k]) => k),
      axisLabel: { rotate: 20 },
    },
    yAxis: { type: "value" },
    series: [
      {
        type: "bar",
        data: alarmTypeEntries.map(([, v]) => ({
          value: v,
          itemStyle: { color: "#3B82F6" },
        })),
      },
    ],
  };

  // --- Table columns ---

  type TopNamespace = (typeof topNamespaces)[number];
  type TopTarget = (typeof topTargets)[number];

  const namespaceColumns: Column<TopNamespace>[] = [
    { key: "namespace", title: t("operations.reports.kubeColNamespace") },
    { key: "clusterName", title: t("operations.reports.kubeColCluster"), width: "160px" },
    { key: "count", title: t("operations.reports.kubeColCount"), align: "right", width: "100px" },
  ];

  const targetColumns: Column<TopTarget>[] = [
    { key: "target", title: t("operations.reports.kubeColTarget") },
    { key: "namespace", title: t("operations.reports.kubeColNamespace"), width: "140px" },
    {
      key: "severity",
      title: t("operations.reports.colSeverity"),
      width: "100px",
      render: (r) => <SeverityTag level={r.severity as Severity} />,
    },
    { key: "count", title: t("operations.reports.kubeColCount"), align: "right", width: "100px" },
  ];

  return (
    <div className="space-y-6">
      {/* Export PDF */}
      <div className="flex justify-end">
        <Button variant="ghost" onClick={handleExportPdf}>
          <Download size={15} />
          {t("operations.reports.exportPdf")}
        </Button>
      </div>

      {/* Row 1: 运行时告警 StatCards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard
          label={t("operations.reports.kubeStatTotalAlarms")}
          value={summary.totalAlarms}
          icon={AlertTriangle}
          tone="danger"
        />
        <StatCard
          label={t("operations.reports.kubeStatPending")}
          value={summary.pendingAlarms}
          icon={Server}
          tone="warning"
        />
        <StatCard
          label={t("operations.reports.kubeStatProcessed")}
          value={summary.processedAlarms}
          icon={CheckCircle2}
          tone="success"
        />
        <StatCard
          label={t("operations.reports.kubeStatIgnored")}
          value={summary.ignoredAlarms}
          icon={MinusCircle}
        />
        <StatCard
          label={t("operations.reports.kubeStatClusters")}
          value={summary.clusterCount}
          icon={Network}
        />
      </div>

      {/* Row 2: CIS 基线 StatCards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard
          label={t("operations.reports.kubeStatBaselineChecks")}
          value={baselineOverview.totalChecks}
          icon={ShieldCheck}
        />
        <StatCard
          label={t("operations.reports.kubeStatPassed")}
          value={baselineOverview.passed}
          icon={CheckCircle2}
          tone="success"
        />
        <StatCard
          label={t("operations.reports.kubeStatFailed")}
          value={baselineOverview.failed}
          icon={XCircle}
          tone="danger"
        />
        <StatCard
          label={t("operations.reports.kubeStatPassRate")}
          value={`${baselineOverview.passRate.toFixed(1)}%`}
          icon={ShieldCheck}
          tone="success"
        />
        <StatCard
          label={t("operations.reports.kubeStatActiveAlerts")}
          value={baselineAlerts.active}
          icon={AlertTriangle}
          tone="warning"
        />
      </div>

      {/* 4 Charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {baselineSevEntries.length > 0 && (
          <ChartCard title={t("operations.reports.kubeChartBaselineSeverity")} option={baselineSeverityOption} />
        )}
        {baselineCatEntries.length > 0 && (
          <ChartCard
            title={t("operations.reports.kubeChartBaselineCategory")}
            option={baselineCategoryOption}
            height={baselineCatEntries.length > 8 ? 320 : 240}
          />
        )}
        {alarmSevEntries.length > 0 && (
          <ChartCard title={t("operations.reports.kubeChartAlarmSeverity")} option={alarmSeverityOption} />
        )}
        {alarmTypeEntries.length > 0 && (
          <ChartCard title={t("operations.reports.kubeChartAlarmType")} option={alarmTypeOption} />
        )}
      </div>

      {/* Top10 Namespace */}
      <Card>
        <CardHeader title={t("operations.reports.kubeTopNamespaces")} />
        <DataTable<TopNamespace>
          columns={namespaceColumns}
          rows={topNamespaces ?? []}
          rowKey={(r) => `${r.clusterName}/${r.namespace}`}
        />
      </Card>

      {/* Top10 影响目标 */}
      <Card>
        <CardHeader title={t("operations.reports.kubeTopTargets")} />
        <DataTable<TopTarget>
          columns={targetColumns}
          rows={topTargets ?? []}
          rowKey={(r) => `${r.namespace}/${r.target}`}
        />
      </Card>
    </div>
  );
}
