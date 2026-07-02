"use client";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Bug, ShieldCheck, ShieldAlert, Percent, Clock } from "lucide-react";
import { vulnApi } from "@/lib/api/vuln";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { ChartCard } from "@/components/ui/ChartCard";
import { EmptyState } from "@/components/ui/EmptyState";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { SeverityTag } from "@/components/ui/Tag";
import type { Severity } from "@/lib/api/types";
import type { RemediationHostStat } from "@/lib/api/types";

const KNOWN_SEV: Severity[] = ["critical", "high", "medium", "low"];

const buildSevLabel = (t: TFunction): Record<string, string> => ({
  critical: t("common.severity.critical"),
  high: t("common.severity.high"),
  medium: t("common.severity.medium"),
  low: t("common.severity.low"),
  none: t("vuln.remediation.sevNone"),
});

function formatMttr(hours: number, t: TFunction): string {
  if (!hours || hours <= 0) return "—";
  if (hours < 24) return t("vuln.remediation.mttrHours", { n: hours.toFixed(1) });
  return t("vuln.remediation.mttrDays", { n: (hours / 24).toFixed(1) });
}

export default function RemediationPage() {
  const { t } = useTranslation();
  const SEV_LABEL = buildSevLabel(t);
  const { data, isLoading } = useQuery({
    queryKey: ["vuln-remediation-stats"],
    queryFn: () => vulnApi.remediationReport(),
  });

  if (isLoading) {
    return <Card className="p-10 text-center text-muted">{t("common.loading")}</Card>;
  }
  if (!data) {
    return <EmptyState title={t("vuln.remediation.loadError")} desc="" />;
  }

  const bySeverity = data.bySeverity ?? [];
  const topUnpatched = data.topUnpatched ?? [];

  const severityOption = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    legend: { data: [t("vuln.remediation.legendPatched"), t("vuln.remediation.legendUnpatched")], bottom: 0 },
    grid: { left: "3%", right: "4%", top: 16, bottom: 36, containLabel: true },
    xAxis: { type: "category", data: bySeverity.map((s) => SEV_LABEL[s.severity] ?? s.severity) },
    yAxis: { type: "value" },
    series: [
      { name: t("vuln.remediation.legendPatched"), type: "bar", stack: "total", data: bySeverity.map((s) => s.patched), itemStyle: { color: "#22C55E" } },
      { name: t("vuln.remediation.legendUnpatched"), type: "bar", stack: "total", data: bySeverity.map((s) => s.unpatched), itemStyle: { color: "#EF4444" } },
    ],
  };

  const topColumns: Column<RemediationHostStat>[] = [
    { key: "hostname", title: t("common.host"), render: (r) => <span className="font-medium text-ink">{r.hostname || r.hostId}</span> },
    { key: "ip", title: "IP", render: (r) => <span className="font-mono text-xs text-muted">{r.ip || "—"}</span> },
    { key: "total", title: t("vuln.remediation.colTotal"), render: (r) => <span className="tabular-nums text-ink">{r.total}</span> },
    { key: "patched", title: t("vuln.remediation.colPatched"), render: (r) => <span className="tabular-nums text-success">{r.patched}</span> },
    {
      key: "unpatched",
      title: t("vuln.remediation.colUnpatched"),
      render: (r) => <span className="tabular-nums text-danger">{r.total - r.patched}</span>,
    },
  ];

  return (
    <div className="space-y-6">
      {/* 概览 */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard compact label={t("vuln.remediation.statTotalVulns")} value={data.totalVulns} icon={Bug} />
        <StatCard compact label={t("vuln.remediation.statPatched")} value={data.patchedVulns} icon={ShieldCheck} tone="success" />
        <StatCard compact label={t("vuln.remediation.statUnpatched")} value={data.unpatchedVulns} icon={ShieldAlert} tone="danger" />
        <StatCard compact label={t("vuln.remediation.statRate")} value={`${(data.remediationRate || 0).toFixed(1)}%`} icon={Percent} tone="success" />
        <StatCard compact label={t("vuln.remediation.statMttr")} value={formatMttr(data.mttr, t)} icon={Clock} />
      </div>

      {/* 按级别 + 图表 */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title={t("vuln.remediation.bySeverityTitle")} />
          <div className="px-5 pb-5">
            {bySeverity.length === 0 ? (
              <EmptyState title={t("vuln.remediation.emptySeverity")} desc="" />
            ) : (
              <div className="space-y-2.5">
                {bySeverity.map((s) => {
                  const rate = s.total > 0 ? (s.patched / s.total) * 100 : 0;
                  return (
                    <div key={s.severity} className="space-y-1">
                      <div className="flex items-center justify-between text-sm">
                        <div className="flex items-center gap-2">
                          {KNOWN_SEV.includes(s.severity as Severity) ? (
                            <SeverityTag level={s.severity as Severity} />
                          ) : (
                            <span className="text-muted">{SEV_LABEL[s.severity] ?? s.severity}</span>
                          )}
                          <span className="text-faint tabular-nums">{t("vuln.remediation.countItems", { n: s.total })}</span>
                        </div>
                        <span className="tabular-nums text-muted">
                          <span className="text-success">{s.patched}</span> /{" "}
                          <span className="text-danger">{s.unpatched}</span>
                        </span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-border">
                        <div className="h-full rounded-full bg-success" style={{ width: `${rate}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </Card>

        {bySeverity.length > 0 ? (
          <ChartCard title={t("vuln.remediation.severityDistTitle")} option={severityOption} />
        ) : (
          <Card>
            <CardHeader title={t("vuln.remediation.severityDistTitle")} />
            <EmptyState title={t("common.noData")} desc="" />
          </Card>
        )}
      </div>

      {/* 未修复 TopN */}
      <Card>
        <CardHeader title={t("vuln.remediation.topUnpatchedTitle")} />
        <div className="px-1 pb-2">
          {topUnpatched.length === 0 ? (
            <EmptyState title={t("vuln.remediation.emptyTopUnpatched")} desc="" />
          ) : (
            <DataTable columns={topColumns} rows={topUnpatched} rowKey={(r) => r.hostId} />
          )}
        </div>
      </Card>
    </div>
  );
}
