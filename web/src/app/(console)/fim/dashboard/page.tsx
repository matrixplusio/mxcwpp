"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { FileText, Clock, AlertTriangle, ShieldAlert, FilePlus, FileMinus, FileEdit } from "lucide-react";
import { fimApi } from "@/lib/api/fim";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { ChartCard } from "@/components/ui/ChartCard";
import { EmptyState } from "@/components/ui/EmptyState";
import { baseGrid, axisStyle, softTooltip, chartColors } from "@/lib/echartsTheme";

function fmtNum(n: number) {
  return (n ?? 0).toLocaleString();
}

export default function FimDashboardPage() {
  const { t } = useTranslation();
  const categoryLabel: Record<string, string> = {
    binary: t("fim.category.binary"),
    config: t("fim.category.config"),
    auth: t("fim.category.auth"),
    log: t("fim.category.log"),
    other: t("fim.category.other"),
  };
  const { data, isLoading, isError } = useQuery({
    queryKey: ["fim-stats"],
    queryFn: () => fimApi.getEventStats(),
  });
  // 取不到就明说取不到：`?? 0` 会把"后端没答上来"渲染成 0，
  // 看板上读起来像"环境干净"。
  const statState = { error: isError, loading: isLoading };

  if (isLoading) {
    return <Card className="p-10 text-center text-muted">{t("fim.dashboard.loading")}</Card>;
  }
  if (!data) {
    return <EmptyState title={t("fim.dashboard.noData")} desc="" />;
  }

  const trend = data.trend ?? [];
  const trendOption = {
    color: chartColors,
    grid: baseGrid,
    tooltip: { trigger: "axis", ...softTooltip },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: trend.map((d) => (d.date.length >= 10 ? d.date.slice(5, 10) : d.date)),
      ...axisStyle,
    },
    yAxis: { type: "value", ...axisStyle },
    series: [
      {
        name: t("fim.dashboard.trendSeries"),
        type: "line",
        smooth: true,
        showSymbol: false,
        lineStyle: { width: 2.5 },
        areaStyle: { opacity: 0.06 },
        data: trend.map((d) => d.count),
      },
    ],
  };

  const categories = Object.entries(data.by_category ?? {});
  const maxCategory = categories.reduce((m, [, v]) => Math.max(m, v), 0) || 1;
  const topHosts = data.top_hosts ?? [];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
        <StatCard compact label={t("fim.dashboard.statTotal")} value={fmtNum(data.total)} {...statState} icon={FileText} tone="default" />
        <StatCard compact label={t("fim.dashboard.statPending")} value={fmtNum(data.pending)} {...statState} icon={Clock} tone="warning" />
        <StatCard compact label={t("fim.dashboard.statCritical")} value={fmtNum(data.critical)} {...statState} icon={ShieldAlert} tone="danger" />
        <StatCard compact label={t("fim.dashboard.statHigh")} value={fmtNum(data.high)} {...statState} icon={AlertTriangle} tone="warning" />
        <StatCard compact label={t("fim.dashboard.statAdded")} value={fmtNum(data.added)} {...statState} icon={FilePlus} tone="default" />
        <StatCard compact label={t("fim.dashboard.statRemoved")} value={fmtNum(data.removed)} {...statState} icon={FileMinus} tone="danger" />
        <StatCard compact label={t("fim.dashboard.statChanged")} value={fmtNum(data.changed)} {...statState} icon={FileEdit} tone="default" />
      </div>

      <ChartCard title={t("fim.dashboard.trendTitle")} option={trendOption} height={300} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={t("fim.dashboard.byCategoryTitle")} />
          <div className="px-5 pb-5">
            {categories.length === 0 ? (
              <EmptyState title={t("fim.dashboard.emptyCategory")} desc="" />
            ) : (
              <div className="space-y-2.5">
                {categories.map(([k, v]) => (
                  <div key={k} className="space-y-1">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted">{categoryLabel[k] ?? k}</span>
                      <span className="tabular-nums text-ink">{fmtNum(v)}</span>
                    </div>
                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-muted">
                      <div
                        className="h-full rounded-full bg-primary"
                        style={{ width: `${Math.round((v / maxCategory) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title={t("fim.dashboard.topHostsTitle")} />
          <div className="px-5 pb-5">
            {topHosts.length === 0 ? (
              <EmptyState title={t("fim.dashboard.emptyHosts")} desc="" />
            ) : (
              <div className="space-y-1.5 text-sm">
                {topHosts.map((h, i) => (
                  <div
                    key={h.host_id || `${h.hostname}-${i}`}
                    className="flex items-center justify-between border-b border-border/50 py-1.5 last:border-0"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="w-5 shrink-0 text-faint tabular-nums">{i + 1}</span>
                      <span className="truncate text-ink">{h.hostname || h.host_id}</span>
                    </span>
                    <span className="shrink-0 tabular-nums text-muted">{fmtNum(h.count)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
