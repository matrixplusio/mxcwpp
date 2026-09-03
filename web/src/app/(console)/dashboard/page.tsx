"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { CalendarRange } from "lucide-react";
import { dashboardApi } from "@/lib/api/dashboard";
import { PageHeader } from "@/components/ui/PageHeader";
import { KpiRow } from "@/components/dashboard/KpiRow";
import { AlertTrendChart } from "@/components/dashboard/AlertTrendChart";
import { SeverityPie } from "@/components/dashboard/SeverityPie";
import { HealthRadar } from "@/components/dashboard/HealthRadar";
import { LatestAlertsTable } from "@/components/dashboard/LatestAlertsTable";
import { StorylineList } from "@/components/dashboard/StorylineList";

function RangePill() {
  const { t } = useTranslation();
  return (
    <div className="inline-flex items-center gap-2 h-9 rounded-control border border-border bg-surface px-3 text-sm text-muted">
      <CalendarRange size={15} className="text-faint" />
      {t("dashboard.last7Days")}
    </div>
  );
}

export default function DashboardPage() {
  const { t } = useTranslation();
  const { data, isLoading, isError } = useQuery({ queryKey: ["dashboard-stats"], queryFn: dashboardApi.getStats });

  return (
    <>
      <PageHeader title={t("dashboard.title")} desc={t("dashboard.desc")} extra={<RangePill />} />
      {isLoading && <div className="text-muted">{t("common.loading")}</div>}
      {isError && <div className="text-danger">{t("dashboard.loadError")}</div>}
      {data && (
        <div className="space-y-5">
          <KpiRow s={data} />
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <div className="lg:col-span-2"><AlertTrendChart data={data.alertTrend} /></div>
            <SeverityPie s={data} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            <HealthRadar s={data} />
            <div className="lg:col-span-2"><LatestAlertsTable rows={data.latestAlerts} /></div>
          </div>
          <StorylineList rows={data.storylineTop} />
        </div>
      )}
    </>
  );
}
