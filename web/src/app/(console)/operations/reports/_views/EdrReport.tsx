"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  AlertTriangle,
  Download,
  Shield,
  ShieldCheck,
  ShieldOff,
  Activity,
  Cpu,
  Globe,
  Zap,
  BookOpen,
  Eye,
  MinusCircle,
  TrendingUp,
  TrendingDown,
  Minus,
} from "lucide-react";
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

const TACTIC_COLORS: Record<string, string> = {
  initial_access: "#EF4444",
  execution: "#F97316",
  persistence: "#FB923C",
  privilege_escalation: "#FBBF24",
  defense_evasion: "#A78BFA",
  credential_access: "#EC4899",
  discovery: "#38BDF8",
  lateral_movement: "#34D399",
  collection: "#6EE7B7",
  exfiltration: "#F472B6",
  command_and_control: "#818CF8",
  impact: "#DC2626",
  other: "#94A3B8",
};

export function EdrReport({ range }: Props) {
  const { t } = useTranslation();

  const SEV_LABEL: Record<string, string> = {
    critical: t("common.severity.critical"),
    high: t("common.severity.high"),
    medium: t("common.severity.medium"),
    low: t("common.severity.low"),
  };

  const { data, isLoading } = useQuery({
    queryKey: ["reports-edr", range.start, range.end],
    queryFn: () => reportsApi.edrModule(range),
  });

  function handleExportPdf() {
    void reportsApi.downloadPdf(
      "/reports/edr/pdf",
      { start_time: range.start, end_time: range.end },
      "edr-report.pdf",
    );
  }

  if (isLoading && !data) {
    return <Card className="p-10 text-center text-muted">{t("operations.reports.loading")}</Card>;
  }

  if (!data) {
    return <EmptyState title={t("operations.reports.emptyData")} desc="" />;
  }

  const {
    meta,
    summary,
    severityDistribution,
    tacticDistribution,
    topRules,
    topHosts,
    topStories,
    suppressionStats,
    trend,
    rawEventStats,
    autoResponseStats,
    iocStats,
    ruleEfficacy,
    improvements,
  } = data;

  // --- Trend display ---
  const growthAbs = Math.abs(trend?.growthPercent ?? 0).toFixed(1);
  const trendLabel =
    trend?.direction === "up"
      ? `↑ ${growthAbs}%`
      : trend?.direction === "down"
        ? `↓ ${growthAbs}%`
        : `→ ${growthAbs}%`;

  // --- Chart: severity pie ---
  const sevEntries = Object.entries(severityDistribution ?? {}).filter(([, v]) => v > 0);
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

  // --- Chart: tactic bar ---
  const tacticEntries = Object.entries(tacticDistribution ?? {})
    .filter(([, v]) => v > 0)
    .sort(([, a], [, b]) => (b as number) - (a as number));
  const tacticOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: "3%", right: "8%", bottom: "3%", containLabel: true },
    xAxis: { type: "value" },
    yAxis: {
      type: "category",
      data: tacticEntries.map(([k]) => k),
    },
    series: [
      {
        type: "bar",
        data: tacticEntries.map(([k, v]) => ({
          value: v,
          itemStyle: { color: TACTIC_COLORS[k] ?? "#6366F1" },
        })),
      },
    ],
  };

  // --- Chart: event type pie (rawEventStats) ---
  const eventsByTypeEntries = (rawEventStats?.eventsByType ?? []).filter((r) => r.count > 0);
  const eventsByTypeOption = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", left: "left", type: "scroll" },
    series: [
      {
        type: "pie",
        radius: ["35%", "65%"],
        data: eventsByTypeEntries.map((r) => ({ name: r.event_type, value: r.count })),
      },
    ],
  };

  // --- Chart: events by hour line ---
  const eventsByHour = rawEventStats?.eventsByHour ?? [];
  const eventsByHourOption = {
    tooltip: { trigger: "axis" },
    grid: { left: "3%", right: "4%", bottom: "3%", containLabel: true },
    xAxis: {
      type: "category",
      data: eventsByHour.map((r) => String(r.hour)),
      axisLabel: { rotate: 30, fontSize: 10 },
    },
    yAxis: { type: "value" },
    series: [
      {
        type: "line",
        smooth: true,
        data: eventsByHour.map((r) => r.count),
        itemStyle: { color: "#3B82F6" },
        areaStyle: { color: "rgba(59,130,246,0.1)" },
      },
    ],
  };

  // --- Table types ---
  type TopRule = (typeof topRules)[number];
  type TopHost = (typeof topHosts)[number];
  type TopStory = (typeof topStories)[number];
  type TopHostByEvent = NonNullable<typeof rawEventStats>["topHostsByEvent"][number];
  type TopExe = NonNullable<typeof rawEventStats>["topExe"][number];
  type ZeroHit = (typeof ruleEfficacy.topZeroHit)[number];
  type Suppress = (typeof suppressionStats)[number];

  // --- Table columns ---
  const ruleColumns: Column<TopRule>[] = [
    { key: "title", title: t("operations.reports.edrColTitle") },
    { key: "category", title: t("operations.reports.colCategory"), width: "130px" },
    {
      key: "severity",
      title: t("operations.reports.colSeverity"),
      width: "100px",
      render: (r) => <SeverityTag level={r.severity as Severity} />,
    },
    { key: "count", title: t("operations.reports.edrColCount"), align: "right", width: "90px" },
  ];

  const hostColumns: Column<TopHost>[] = [
    { key: "hostname", title: t("operations.reports.edrColHostname") },
    { key: "count", title: t("operations.reports.edrColCount"), align: "right", width: "100px" },
  ];

  const storyColumns: Column<TopStory>[] = [
    { key: "hostname", title: t("operations.reports.edrColHostname"), width: "160px" },
    { key: "phase", title: t("operations.reports.edrColPhase"), width: "130px" },
    {
      key: "severity",
      title: t("operations.reports.colSeverity"),
      width: "100px",
      render: (r) => <SeverityTag level={r.severity as Severity} />,
    },
    {
      key: "event_count",
      title: t("operations.reports.edrColEventCount"),
      align: "right",
      width: "80px",
    },
    {
      key: "alert_count",
      title: t("operations.reports.edrColAlertCount"),
      align: "right",
      width: "80px",
    },
    {
      key: "risk_score",
      title: t("operations.reports.edrColRiskScore"),
      align: "right",
      width: "90px",
      render: (r) => r.risk_score.toFixed(1),
    },
  ];

  const topHostByEventColumns: Column<TopHostByEvent>[] = [
    { key: "hostname", title: t("operations.reports.edrColHostname") },
    { key: "count", title: t("operations.reports.edrColCount"), align: "right", width: "100px" },
  ];

  const topExeColumns: Column<TopExe>[] = [
    { key: "exe", title: t("operations.reports.edrColExe") },
    { key: "count", title: t("operations.reports.edrColCount"), align: "right", width: "100px" },
  ];

  const zeroHitColumns: Column<ZeroHit>[] = [
    { key: "name", title: t("operations.reports.edrColRuleName") },
    { key: "category", title: t("operations.reports.edrColRuleCategory"), width: "140px" },
  ];

  const suppressColumns: Column<Suppress>[] = [
    { key: "reason", title: t("operations.reports.edrColReason") },
    {
      key: "count",
      title: t("operations.reports.edrColCount"),
      align: "right",
      width: "100px",
    },
  ];

  // Computed for raw events block
  const avgPerHost =
    rawEventStats?.uniqueHosts && rawEventStats.uniqueHosts > 0
      ? Math.round(rawEventStats.totalEvents / rawEventStats.uniqueHosts)
      : 0;
  const alertConvRate =
    rawEventStats?.totalEvents && rawEventStats.totalEvents > 0
      ? ((summary.totalAlerts / rawEventStats.totalEvents) * 100).toFixed(3)
      : "—";

  return (
    <div className="space-y-6">
      {/* Export PDF */}
      <div className="flex justify-end">
        <Button variant="ghost" onClick={handleExportPdf}>
          <Download size={15} />
          {t("operations.reports.exportPdf")}
        </Button>
      </div>

      {/* === Section 1: Meta StatCards Row 1 — online hosts / enabled rules / total alerts / active / ignored === */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard
          label={t("operations.reports.edrOnlineHosts")}
          value={meta.onlineHosts}
          icon={Shield}
        />
        <StatCard
          label={`${t("operations.reports.edrEnabledRules")} / ${t("operations.reports.edrTotalRules")}`}
          value={`${meta.enabledRules} / ${meta.totalRules}`}
          icon={ShieldCheck}
          tone="success"
        />
        <StatCard
          label={t("operations.reports.edrTotalAlerts")}
          value={summary.totalAlerts}
          icon={AlertTriangle}
          tone="danger"
        />
        <StatCard
          label={t("operations.reports.edrActive")}
          value={summary.activeAlerts}
          icon={Activity}
          tone="warning"
        />
        <StatCard
          label={t("operations.reports.edrIgnoredAlerts")}
          value={summary.ignoredAlerts}
          icon={MinusCircle}
        />
      </div>

      {/* === Section 1b: Meta StatCards Row 2 — affected hosts / stories / high-risk stories / trend === */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard
          label={t("operations.reports.edrAffectedHosts")}
          value={summary.affectedHosts}
          icon={Globe}
          tone="warning"
        />
        <StatCard
          label={t("operations.reports.edrTotalStories")}
          value={summary.totalStories}
          icon={BookOpen}
        />
        <StatCard
          label={t("operations.reports.edrHighRiskStories")}
          value={summary.highRiskStories}
          icon={ShieldOff}
          tone="danger"
        />
        {trend && (
          <StatCard
            label={t("operations.reports.edrTrend")}
            value={trendLabel}
            icon={trend.direction === "up" ? TrendingUp : trend.direction === "down" ? TrendingDown : Minus}
            tone={trend.direction === "up" ? "danger" : trend.direction === "down" ? "success" : "default"}
          />
        )}
      </div>

      {/* === Section 2: Charts — severity pie + MITRE tactic bar === */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {sevEntries.length > 0 && (
          <ChartCard title={t("operations.reports.edrSeverityDist")} option={severityOption} />
        )}
        {tacticEntries.length > 0 && (
          <ChartCard
            title={t("operations.reports.edrTactic")}
            option={tacticOption}
            height={tacticEntries.length > 8 ? 360 : 280}
          />
        )}
      </div>

      {/* === Section 3: Top10 规则 + Top10 主机 === */}
      <Card>
        <CardHeader title={t("operations.reports.edrTopRules")} />
        <DataTable<TopRule>
          columns={ruleColumns}
          rows={topRules ?? []}
          rowKey={(r) => r.title}
        />
      </Card>

      <Card>
        <CardHeader title={t("operations.reports.edrTopHosts")} />
        <DataTable<TopHost>
          columns={hostColumns}
          rows={topHosts ?? []}
          rowKey={(r) => r.host_id}
        />
      </Card>

      {/* === Section 4: ClickHouse 原始事件块 (conditional on available) === */}
      {rawEventStats?.available && (
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-foreground">
            {t("operations.reports.edrRawEventsTitle")}
          </h3>

          {/* 4 stat cards */}
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard
              label={t("operations.reports.edrTotalEvents")}
              value={rawEventStats.totalEvents.toLocaleString()}
              icon={Activity}
            />
            <StatCard
              label={t("operations.reports.edrUniqueHosts")}
              value={rawEventStats.uniqueHosts}
              icon={Cpu}
            />
            <StatCard
              label={t("operations.reports.edrAvgPerHost")}
              value={avgPerHost.toLocaleString()}
              icon={Eye}
            />
            <StatCard
              label={t("operations.reports.edrAlertConvRate")}
              value={alertConvRate === "—" ? "—" : `${alertConvRate}%`}
              icon={Zap}
            />
          </div>

          {/* event type pie + hourly trend line */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {eventsByTypeEntries.length > 0 && (
              <ChartCard
                title={t("operations.reports.edrEventsByType")}
                option={eventsByTypeOption}
              />
            )}
            {eventsByHour.length > 0 && (
              <ChartCard
                title={t("operations.reports.edrEventsByHour")}
                option={eventsByHourOption}
                height={280}
              />
            )}
          </div>

          {/* top hosts by event */}
          {(rawEventStats.topHostsByEvent ?? []).length > 0 && (
            <Card>
              <CardHeader title={t("operations.reports.edrTopHostsByEvent")} />
              <DataTable<TopHostByEvent>
                columns={topHostByEventColumns}
                rows={rawEventStats.topHostsByEvent}
                rowKey={(r) => r.host_id}
              />
            </Card>
          )}

          {/* top exe */}
          {(rawEventStats.topExe ?? []).length > 0 && (
            <Card>
              <CardHeader title={t("operations.reports.edrTopExe")} />
              <DataTable<TopExe>
                columns={topExeColumns}
                rows={rawEventStats.topExe}
                rowKey={(r) => r.exe}
              />
            </Card>
          )}
        </div>
      )}

      {/* === Section 5: 自动响应卡 === */}
      {autoResponseStats && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">
            {t("operations.reports.edrAutoResponseTitle")}
          </h3>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard
              label={t("operations.reports.edrNetworkBlocks")}
              value={autoResponseStats.networkBlocks}
              icon={Globe}
              tone="danger"
            />
            <StatCard
              label={t("operations.reports.edrHostIsolations")}
              value={autoResponseStats.hostIsolations}
              icon={ShieldOff}
              tone="warning"
            />
            <StatCard
              label={t("operations.reports.edrProcessKills")}
              value={autoResponseStats.processKills}
              icon={Zap}
              tone="warning"
            />
            <StatCard
              label={t("operations.reports.edrAutoTotal")}
              value={autoResponseStats.total}
              icon={Activity}
            />
          </div>
        </div>
      )}

      {/* === Section 6: IOC / 内存威胁卡 === */}
      {iocStats && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-foreground">
            {t("operations.reports.edrIocTitle")}
          </h3>
          <div className="flex flex-wrap gap-4">
            <StatCard
              label={t("operations.reports.edrIocSnapshots")}
              value={iocStats.iocSnapshots}
              icon={Eye}
            />
            <StatCard
              label={t("operations.reports.edrMemoryThreats")}
              value={iocStats.memoryThreats}
              icon={ShieldOff}
              tone="danger"
            />
          </div>
          {(iocStats.topIOCTypes ?? []).length > 0 && (
            <div className="flex flex-wrap gap-2 pt-1">
              <span className="text-xs text-muted">{t("operations.reports.edrTopIOCTypes")}：</span>
              {iocStats.topIOCTypes.map((item) => (
                <span
                  key={item.technique}
                  className="rounded-full border border-border bg-surface px-2 py-0.5 text-xs"
                >
                  {item.technique}
                  <span className="ml-1 text-muted">×{item.count}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* === Section 7: 规则有效性卡 + 零命中规则表 === */}
      {ruleEfficacy && (
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-foreground">
            {t("operations.reports.edrRuleEfficacyTitle")}
          </h3>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard
              label={t("operations.reports.edrHitRules")}
              value={ruleEfficacy.hitRules}
              icon={ShieldCheck}
              tone="success"
            />
            <StatCard
              label={t("operations.reports.edrEnabledRules")}
              value={ruleEfficacy.enabledRules}
              icon={Shield}
            />
            <StatCard
              label={t("operations.reports.edrZeroHitRules")}
              value={ruleEfficacy.zeroHitRules}
              icon={ShieldOff}
              tone={ruleEfficacy.zeroHitRules > 20 ? "danger" : "default"}
            />
            <StatCard
              label={t("operations.reports.edrHitRate")}
              value={`${ruleEfficacy.hitRate.toFixed(1)}%`}
              icon={Activity}
              tone={ruleEfficacy.hitRate >= 50 ? "success" : "warning"}
            />
          </div>
          {/* hit rate progress bar */}
          <Card className="p-4">
            <div className="mb-1 flex justify-between text-xs text-muted">
              <span>{t("operations.reports.edrHitRate")}</span>
              <span>{ruleEfficacy.hitRate.toFixed(1)}%</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-surface-alt">
              <div
                className="h-full rounded-full bg-blue-500 transition-all"
                style={{ width: `${Math.min(ruleEfficacy.hitRate, 100)}%` }}
              />
            </div>
          </Card>

          {(ruleEfficacy.topZeroHit ?? []).length > 0 && (
            <Card>
              <CardHeader title={t("operations.reports.edrZeroHitTable")} />
              <DataTable<ZeroHit>
                columns={zeroHitColumns}
                rows={ruleEfficacy.topZeroHit}
                rowKey={(r) => String(r.id)}
              />
            </Card>
          )}
        </div>
      )}

      {/* === Section 8: 改进建议 === */}
      {(improvements ?? []).length > 0 && (
        <Card className="p-4">
          <h3 className="mb-3 text-sm font-semibold text-foreground">
            {t("operations.reports.edrImprovementsTitle")}
          </h3>
          <ol className="list-inside list-decimal space-y-2">
            {improvements.map((item, i) => (
              <li key={i} className="text-sm text-foreground">
                {item}
              </li>
            ))}
          </ol>
        </Card>
      )}

      {/* === Section 9: Top5 高风险故事线 === */}
      {(topStories ?? []).length > 0 && (
        <Card>
          <CardHeader title={t("operations.reports.edrTopStoriesTitle")} />
          <DataTable<TopStory>
            columns={storyColumns}
            rows={topStories}
            rowKey={(r) => r.story_id}
          />
        </Card>
      )}

      {/* === Section 10: 误报抑制统计 === */}
      {(suppressionStats ?? []).length > 0 && (
        <Card>
          <CardHeader title={t("operations.reports.edrSuppressionTitle")} />
          <DataTable<Suppress>
            columns={suppressColumns}
            rows={suppressionStats}
            rowKey={(r) => r.reason}
          />
        </Card>
      )}
    </div>
  );
}
