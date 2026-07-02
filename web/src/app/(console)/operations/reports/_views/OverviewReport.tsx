"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useRouter } from "next/navigation";
import { Server, ShieldCheck, FileText, ListChecks } from "lucide-react";
import { reportsApi } from "@/lib/api/reports";
import type { DateRange } from "@/lib/api/reports";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { ChartCard } from "@/components/ui/ChartCard";
import { DataTable } from "@/components/ui/DataTable";
import { EmptyState } from "@/components/ui/EmptyState";
import type { Column } from "@/components/ui/DataTable";
import type { TopFailedRule, TopRiskHost } from "@/lib/api/types";

interface Props {
  range: DateRange;
}

export function OverviewReport({ range }: Props) {
  const { t } = useTranslation();
  const router = useRouter();

  const SEV_LABEL: Record<string, string> = {
    critical: t("common.severity.critical"),
    high: t("common.severity.high"),
    medium: t("common.severity.medium"),
    low: t("common.severity.low"),
  };

  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ["reports-overview-stats", range.start, range.end],
    queryFn: () => reportsApi.stats(range),
  });

  const { data: scoreTrend, isLoading: scoreTrendLoading } = useQuery({
    queryKey: ["reports-score-trend", range.start, range.end],
    queryFn: () =>
      reportsApi.baselineScoreTrend({ start_time: range.start, end_time: range.end, interval: "day" }),
  });

  const { data: checkTrend, isLoading: checkTrendLoading } = useQuery({
    queryKey: ["reports-check-trend", range.start, range.end],
    queryFn: () =>
      reportsApi.checkResultTrend({ start_time: range.start, end_time: range.end, interval: "day" }),
  });

  const { data: topRules, isLoading: rulesLoading } = useQuery({
    queryKey: ["reports-top-failed-rules"],
    queryFn: () => reportsApi.topFailedRules(10),
  });

  const { data: topHosts, isLoading: hostsLoading } = useQuery({
    queryKey: ["reports-top-risk-hosts"],
    queryFn: () => reportsApi.topRiskHosts(10),
  });

  if (statsLoading && !statsData) {
    return (
      <Card className="p-10 text-center text-muted">{t("operations.reports.loading")}</Card>
    );
  }

  if (!statsData) {
    return <EmptyState title={t("operations.reports.emptyData")} desc="" />;
  }

  const { hostStats, baselineStats, policyStats, taskStats } = statsData;

  // --- ECharts options ---

  const hostStatusOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [
      {
        type: "pie",
        radius: ["40%", "70%"],
        data: [
          { value: hostStats.online, name: t("operations.reports.online"), itemStyle: { color: "#22C55E" } },
          { value: hostStats.offline, name: t("operations.reports.offline"), itemStyle: { color: "#EF4444" } },
        ].filter((d) => d.value > 0),
      },
    ],
  };

  const baselineResultOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [
      {
        type: "pie",
        radius: "65%",
        data: [
          { value: baselineStats.passed, name: t("operations.reports.statPassed"), itemStyle: { color: "#22C55E" } },
          { value: baselineStats.failed, name: t("operations.reports.statFailed"), itemStyle: { color: "#EF4444" } },
          { value: baselineStats.warning, name: t("operations.reports.statWarning"), itemStyle: { color: "#F59E0B" } },
        ].filter((d) => d.value > 0),
      },
    ],
  };

  const severityOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
    xAxis: {
      type: "category",
      data: [SEV_LABEL.critical, SEV_LABEL.high, SEV_LABEL.medium, SEV_LABEL.low],
    },
    yAxis: { type: "value" },
    series: [
      {
        type: "bar",
        data: [
          { value: baselineStats.bySeverity.critical, itemStyle: { color: "#EF4444" } },
          { value: baselineStats.bySeverity.high, itemStyle: { color: "#ff7875" } },
          { value: baselineStats.bySeverity.medium, itemStyle: { color: "#ffa940" } },
          { value: baselineStats.bySeverity.low, itemStyle: { color: "#ffc53d" } },
        ],
      },
    ],
  };

  const osEntries = Object.entries(hostStats.byOsFamily);
  const osOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left" },
    series: [{ type: "pie", radius: "65%", data: osEntries.map(([name, value]) => ({ name, value })) }],
  };

  const scoreTrendOption = scoreTrend
    ? {
        tooltip: { trigger: "axis" },
        legend: { data: [t("operations.reports.trendScore"), t("operations.reports.trendPassRate")] },
        grid: { left: "3%", right: "6%", bottom: "3%", containLabel: true },
        xAxis: { type: "category", data: scoreTrend.dates, boundaryGap: false },
        yAxis: [
          { type: "value", name: t("operations.reports.trendScore"), min: 0, max: 100 },
          { type: "value", name: "%", min: 0, max: 100, axisLabel: { formatter: "{value}%" } },
        ],
        series: [
          {
            name: t("operations.reports.trendScore"),
            type: "line",
            yAxisIndex: 0,
            smooth: true,
            data: scoreTrend.scores,
            itemStyle: { color: "#3B82F6" },
            areaStyle: { color: "rgba(59,130,246,0.08)" },
          },
          {
            name: t("operations.reports.trendPassRate"),
            type: "line",
            yAxisIndex: 1,
            smooth: true,
            data: scoreTrend.passRates.map((v) => +v.toFixed(1)),
            itemStyle: { color: "#22C55E" },
            areaStyle: { color: "rgba(34,197,94,0.06)" },
          },
        ],
      }
    : null;

  const checkTrendOption = checkTrend
    ? {
        tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
        legend: {
          data: [
            t("operations.reports.statPassed"),
            t("operations.reports.statFailed"),
            t("operations.reports.statWarning"),
          ],
        },
        grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
        xAxis: { type: "category", data: checkTrend.dates, boundaryGap: false },
        yAxis: { type: "value" },
        series: [
          {
            name: t("operations.reports.statPassed"),
            type: "line",
            stack: "total",
            areaStyle: { color: "rgba(34,197,94,0.3)" },
            smooth: true,
            data: checkTrend.passed,
            itemStyle: { color: "#22C55E" },
          },
          {
            name: t("operations.reports.statWarning"),
            type: "line",
            stack: "total",
            areaStyle: { color: "rgba(245,158,11,0.3)" },
            smooth: true,
            data: checkTrend.warning,
            itemStyle: { color: "#F59E0B" },
          },
          {
            name: t("operations.reports.statFailed"),
            type: "line",
            stack: "total",
            areaStyle: { color: "rgba(239,68,68,0.3)" },
            smooth: true,
            data: checkTrend.failed,
            itemStyle: { color: "#EF4444" },
          },
        ],
      }
    : null;

  // --- Table columns ---

  const ruleColumns: Column<TopFailedRule>[] = [
    { key: "title", title: t("operations.reports.colRuleTitle") },
    {
      key: "severity",
      title: t("operations.reports.colSeverity"),
      width: "90px",
      render: (row) => SEV_LABEL[row.severity] ?? row.severity,
    },
    { key: "category", title: t("operations.reports.colCategory"), width: "120px" },
    {
      key: "affected_hosts",
      title: t("operations.reports.colAffectedHosts"),
      align: "right",
      width: "100px",
    },
  ];

  const hostColumns: Column<TopRiskHost>[] = [
    { key: "hostname", title: t("operations.reports.colHostname") },
    { key: "ip", title: t("common.ip"), width: "140px" },
    {
      key: "score",
      title: t("operations.reports.colScore"),
      align: "right",
      width: "80px",
      render: (row) => String(Math.round(row.score)),
    },
    {
      key: "fail_count",
      title: t("operations.reports.colFailCount"),
      align: "right",
      width: "90px",
    },
  ];

  return (
    <div className="space-y-6">
      {/* 4 StatCards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label={t("operations.reports.statTotalHosts")} value={hostStats.total} icon={Server} />
        <StatCard
          label={t("operations.reports.statTotalChecks")}
          value={baselineStats.totalChecks}
          icon={ShieldCheck}
        />
        <StatCard
          label={t("operations.reports.statTotalPolicies")}
          value={policyStats.total}
          icon={FileText}
        />
        <StatCard
          label={t("operations.reports.statTotalTasks")}
          value={taskStats.total}
          icon={ListChecks}
        />
      </div>

      {/* 4 基础图表 */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ChartCard title={t("operations.reports.chartHostStatus")} option={hostStatusOption} />
        <ChartCard title={t("operations.reports.chartBaselineResult")} option={baselineResultOption} />
        <ChartCard title={t("operations.reports.chartSeverity")} option={severityOption} />
        {osEntries.length > 0 && (
          <ChartCard title={t("operations.reports.chartOs")} option={osOption} />
        )}
      </div>

      {/* 趋势图 */}
      {!scoreTrendLoading && scoreTrendOption && (
        <ChartCard
          title={t("operations.reports.chartScoreTrend")}
          option={scoreTrendOption}
          height={280}
        />
      )}
      {!checkTrendLoading && checkTrendOption && (
        <ChartCard
          title={t("operations.reports.chartCheckTrend")}
          option={checkTrendOption}
          height={280}
        />
      )}

      {/* Top10 失败检查项 */}
      <Card>
        <CardHeader title={t("operations.reports.topFailedRules")} />
        <DataTable<TopFailedRule>
          columns={ruleColumns}
          rows={topRules ?? []}
          rowKey={(r) => r.rule_id}
          loading={rulesLoading}
          onRowClick={(r) => router.push(`/operations/task-report`)}
        />
      </Card>

      {/* Top10 风险主机 */}
      <Card>
        <CardHeader title={t("operations.reports.topRiskHosts")} />
        <DataTable<TopRiskHost>
          columns={hostColumns}
          rows={topHosts ?? []}
          rowKey={(r) => r.host_id}
          loading={hostsLoading}
          onRowClick={(r) =>
            router.push(`/assets/hosts/detail?id=${encodeURIComponent(r.host_id)}`)
          }
        />
      </Card>
    </div>
  );
}
