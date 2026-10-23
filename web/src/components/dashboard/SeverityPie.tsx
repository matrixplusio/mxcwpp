"use client";
import { useTranslation } from "react-i18next";
import { ChartCard } from "@/components/ui/ChartCard";
import { useThemeStore } from "@/stores/theme";
import { severityColors, softTooltip, legendStyle } from "@/lib/echartsTheme";
import type { DashboardStats } from "@/lib/api/types";

export function SeverityPie({ s }: { s: DashboardStats }) {
  const { t } = useTranslation();
  // 富文本里的颜色不走 ChartCard 的暗色覆盖，要自己跟主题：写死深色时暗色下总数看不见
  const dark = useThemeStore((st) => st.mode) === "dark";
  const total = s.criticalAlerts + s.highAlerts + s.mediumAlerts + s.lowAlerts;
  const option = {
    color: severityColors,
    tooltip: { trigger: "item", ...softTooltip },
    legend: { bottom: 0, ...legendStyle },
    series: [{
      type: "pie",
      radius: ["62%", "84%"],
      center: ["50%", "44%"],
      avoidLabelOverlap: false,
      itemStyle: { borderColor: "#fff", borderWidth: 3, borderRadius: 6 },
      label: {
        show: true,
        position: "center",
        formatter: `{a|${total}}\n{b|${t("dashboard.totalAlerts")}}`,
        rich: {
          a: { fontSize: 24, fontWeight: 700, color: dark ? "#E2E8F0" : "#0F172A" },
          b: { fontSize: 12, color: "#94A3B8", padding: [4, 0, 0, 0] },
        },
      },
      emphasis: { label: { show: true } },
      labelLine: { show: false },
      data: [
        { name: t("dashboard.severityCritical"), value: s.criticalAlerts },
        { name: t("dashboard.severityHigh"), value: s.highAlerts },
        { name: t("dashboard.severityMedium"), value: s.mediumAlerts },
        { name: t("dashboard.severityLow"), value: s.lowAlerts },
      ],
    }],
  };
  return <ChartCard title={t("dashboard.alertsBySeverity")} option={option} />;
}
