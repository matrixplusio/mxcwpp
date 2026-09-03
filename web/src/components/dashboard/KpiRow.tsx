"use client";
import { useTranslation } from "react-i18next";
import { StatCard } from "@/components/ui/StatCard";
import { ScoreGauge } from "./ScoreGauge";
import { ServerCog, ServerOff, Bell, Bug, ShieldCheck } from "lucide-react";
import type { DashboardStats } from "@/lib/api/types";
import { STAT_UNKNOWN } from "@/lib/utils/stat";

export function KpiRow({ s }: { s: DashboardStats }) {
  const { t } = useTranslation();
  return (
    <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
      <ScoreGauge score={s.securityScore} />
      <StatCard label={t("dashboard.onlineAgents")} value={s.onlineAgents} icon={ServerCog} />
      <StatCard label={t("dashboard.offlineAgents")} value={s.offlineAgents} icon={ServerOff} tone="warning" />
      <StatCard label={t("dashboard.pendingAlerts")} value={s.pendingAlerts} icon={Bell} tone="danger" />
      <StatCard label={t("dashboard.openVulnerabilities")} value={s.pendingVulnerabilities} icon={Bug} tone="warning" />
      {/* 合规率为 null 表示从未扫过基线或查询失败。渲染成占位符而不是数字——
          此前后端在这两种情况下都返回 100%，大屏因此对一个从没扫过的环境显示「完全合规」。
          色调也不用 success：未知不是好消息。 */}
      <StatCard
        label={t("dashboard.baselineCompliance")}
        value={
          s.baselineHardeningPercent === null
            ? STAT_UNKNOWN
            : `${s.baselineHardeningPercent.toFixed(1)}%`
        }
        icon={ShieldCheck}
        tone={s.baselineHardeningPercent === null ? "default" : "success"}
      />
    </div>
  );
}
