"use client";
import { useTranslation } from "react-i18next";
import { ChartCard } from "@/components/ui/ChartCard";
import { softTooltip } from "@/lib/echartsTheme";
import type { DashboardStats } from "@/lib/api/types";

export function HealthRadar({ s }: { s: DashboardStats }) {
  const { t } = useTranslation();
  const option = {
    color: ["#2563EB"],
    tooltip: { ...softTooltip },
    radar: {
      radius: "62%",
      splitNumber: 4,
      indicator: [
        { name: t("dashboard.radarBaseline"), max: 100 }, { name: t("dashboard.radarHostAlerts"), max: 100 }, { name: t("dashboard.radarVulns"), max: 100 },
        { name: t("dashboard.radarDetection"), max: 100 }, { name: t("dashboard.radarVirus"), max: 100 },
      ],
      axisName: { color: "#94A3B8", fontSize: 12 },
      axisLine: { lineStyle: { color: "rgba(148,163,184,0.25)" } },
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.25)" } },
      splitArea: { areaStyle: { color: ["transparent", "rgba(148,163,184,0.06)"] } },
    },
    series: [{
      type: "radar",
      symbolSize: 4,
      lineStyle: { width: 2 },
      areaStyle: { opacity: 0.12 },
      data: [{
        value: [
          Math.round(100 - s.baselineHostPercent), Math.round(100 - s.hostAlertPercent), Math.round(100 - s.vulnHostPercent),
          Math.round(100 - s.detectionAlertPercent), Math.round(100 - s.virusHostPercent),
        ],
        name: t("dashboard.health"),
      }],
    }],
  };
  return <ChartCard title={t("dashboard.healthRadar")} option={option} />;
}
