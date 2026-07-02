"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Bug, Clock, Download, ListChecks, Lock, Server } from "lucide-react";
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

const ACTION_COLORS: Record<string, string> = {
  detected: "#3B82F6",
  quarantined: "#F59E0B",
  deleted: "#EF4444",
  ignored: "#94A3B8",
};

export function AntivirusReport({ range }: Props) {
  const { t } = useTranslation();

  const SEV_LABEL: Record<string, string> = {
    critical: t("common.severity.critical"),
    high: t("common.severity.high"),
    medium: t("common.severity.medium"),
    low: t("common.severity.low"),
  };

  const ACTION_LABEL: Record<string, string> = {
    detected: t("virus.disposition.detected"),
    quarantined: t("virus.disposition.quarantined"),
    deleted: t("virus.disposition.deleted"),
    ignored: t("virus.disposition.ignored"),
  };

  const { data, isLoading } = useQuery({
    queryKey: ["reports-antivirus", range.start, range.end],
    queryFn: () => reportsApi.antivirusModule(range),
  });

  function handleExportPdf() {
    void reportsApi.downloadPdf(
      "/reports/antivirus/pdf",
      { start_time: range.start, end_time: range.end },
      "antivirus-report.pdf",
    );
  }

  if (isLoading && !data) {
    return <Card className="p-10 text-center text-muted">{t("operations.reports.loading")}</Card>;
  }

  if (!data) {
    return <EmptyState title={t("operations.reports.emptyData")} desc="" />;
  }

  const { summary, severityDistribution, threatTypeDistribution, actionDistribution, topThreats, topAffectedHosts } =
    data;

  // --- Chart options ---

  const sevEntries = Object.entries(severityDistribution).filter(([, v]) => v > 0);
  const severityOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [
      {
        type: "pie",
        radius: ["40%", "70%"],
        data: sevEntries.map(([name, value]) => ({
          name: SEV_LABEL[name] ?? name,
          value,
          itemStyle: { color: SEV_COLORS[name] },
        })),
      },
    ],
  };

  const threatTypeEntries = Object.entries(threatTypeDistribution).filter(([, v]) => v > 0);
  const threatTypeOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [
      {
        type: "pie",
        radius: "65%",
        data: threatTypeEntries.map(([name, value]) => ({
          name: t(`virus.threatType.${name}`, { defaultValue: name }),
          value,
        })),
      },
    ],
  };

  const actionEntries = Object.entries(actionDistribution);
  const actionOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
    xAxis: {
      type: "category",
      data: actionEntries.map(([k]) => ACTION_LABEL[k] ?? k),
    },
    yAxis: { type: "value" },
    series: [
      {
        type: "bar",
        data: actionEntries.map(([k, v]) => ({
          value: v,
          itemStyle: { color: ACTION_COLORS[k] ?? "#3B82F6" },
        })),
      },
    ],
  };

  // --- Table columns ---

  type TopThreat = (typeof topThreats)[number];
  type TopHost = (typeof topAffectedHosts)[number];

  const threatColumns: Column<TopThreat>[] = [
    { key: "threatName", title: t("operations.reports.avColThreatName") },
    {
      key: "severity",
      title: t("operations.reports.colSeverity"),
      width: "100px",
      render: (r) => <SeverityTag level={r.severity as Severity} />,
    },
    {
      key: "count",
      title: t("operations.reports.avColCount"),
      align: "right",
      width: "100px",
    },
    {
      key: "affectedHosts",
      title: t("operations.reports.colAffectedHosts"),
      align: "right",
      width: "120px",
    },
  ];

  const hostColumns: Column<TopHost>[] = [
    { key: "hostname", title: t("operations.reports.colHostname") },
    { key: "ip", title: t("common.ip"), width: "140px" },
    {
      key: "threatCount",
      title: t("operations.reports.avStatTotalThreats"),
      align: "right",
      width: "100px",
    },
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

      {/* 5 StatCards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard label={t("operations.reports.avStatTotalTasks")} value={summary.totalTasks} icon={ListChecks} />
        <StatCard
          label={t("operations.reports.avStatTotalThreats")}
          value={summary.totalThreats}
          icon={Bug}
          tone="danger"
        />
        <StatCard
          label={t("operations.reports.avStatDetected")}
          value={summary.detectedThreats}
          icon={Clock}
          tone="warning"
        />
        <StatCard
          label={t("operations.reports.avStatQuarantined")}
          value={summary.quarantinedThreats}
          icon={Lock}
          tone="success"
        />
        <StatCard label={t("operations.reports.avStatAffectedHosts")} value={summary.affectedHosts} icon={Server} />
      </div>

      {/* 3 Charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {sevEntries.length > 0 && (
          <ChartCard title={t("operations.reports.avChartSeverity")} option={severityOption} />
        )}
        {threatTypeEntries.length > 0 && (
          <ChartCard title={t("operations.reports.avChartThreatType")} option={threatTypeOption} />
        )}
        {actionEntries.length > 0 && (
          <ChartCard title={t("operations.reports.avChartAction")} option={actionOption} />
        )}
      </div>

      {/* Top10 威胁 */}
      <Card>
        <CardHeader title={t("operations.reports.avTopThreats")} />
        <DataTable<TopThreat>
          columns={threatColumns}
          rows={topThreats ?? []}
          rowKey={(r) => r.threatName}
        />
      </Card>

      {/* Top10 受影响主机 */}
      <Card>
        <CardHeader title={t("operations.reports.avTopHosts")} />
        <DataTable<TopHost>
          columns={hostColumns}
          rows={topAffectedHosts ?? []}
          rowKey={(r) => r.hostId}
        />
      </Card>
    </div>
  );
}
