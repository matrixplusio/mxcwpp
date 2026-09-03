"use client";
import { useTranslation } from "react-i18next";
import { ChartCard } from "@/components/ui/ChartCard";
import { severityColors, baseGrid, axisStyle, softTooltip, legendStyle } from "@/lib/echartsTheme";
import type { AlertTrendItem } from "@/lib/api/types";

function fmtDate(v: string) {
  // ISO "2026-06-15T00:00:00+08:00" → "06-15"
  return v.length >= 10 ? v.slice(5, 10) : v;
}

export function AlertTrendChart({ data }: { data: AlertTrendItem[] }) {
  const { t } = useTranslation();
  const keys = ["critical", "high", "medium", "low"] as const;
  const labels = {
    critical: t("dashboard.severityCritical"),
    high: t("dashboard.severityHigh"),
    medium: t("dashboard.severityMedium"),
    low: t("dashboard.severityLow"),
  };
  const option = {
    color: severityColors,
    grid: baseGrid,
    tooltip: { trigger: "axis", ...softTooltip },
    legend: { right: 0, top: 0, ...legendStyle },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: data.map((d) => d.date),
      ...axisStyle,
      axisLabel: { ...axisStyle.axisLabel, formatter: fmtDate },
    },
    yAxis: { type: "value", ...axisStyle },
    series: keys.map((k) => ({
      name: labels[k],
      type: "line",
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 2.5 },
      areaStyle: { opacity: 0.05 },
      data: data.map((d) => d[k]),
    })),
  };
  return <ChartCard title={t("dashboard.alertTrend")} option={option} height={300} />;
}
