"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { monitorApi } from "@/lib/api/monitoring";
import type { ServiceConnection, ServiceInfo, ServiceStatus, MonitorRange } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { ChartCard } from "@/components/ui/ChartCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { StatusTag } from "@/components/ui/Tag";
import { Tabs } from "@/components/ui/Tabs";
import { EmptyState } from "@/components/ui/EmptyState";
import { cn } from "@/lib/utils/cn";
import { chartColors, baseGrid, axisStyle, softTooltip, legendStyle } from "@/lib/echartsTheme";

const buildRangeItems = (t: TFunction) => [
  { key: "1h", label: t("monitoring.range.1h") },
  { key: "6h", label: t("monitoring.range.6h") },
  { key: "24h", label: t("monitoring.range.24h") },
];

type Tone = "success" | "warning" | "danger" | "info" | "neutral";
const statusTone: Record<ServiceStatus, Tone> = { healthy: "success", warning: "warning", error: "danger" };
const buildStatusText = (t: TFunction): Record<ServiceStatus, string> => ({
  healthy: t("monitoring.services.statusHealthy"),
  warning: t("monitoring.services.statusWarning"),
  error: t("monitoring.services.statusError"),
});
const dotColor: Record<ServiceStatus, string> = {
  healthy: "bg-success",
  warning: "bg-warning",
  error: "bg-danger",
};

function formatQps(qps: number): string {
  if (qps === 0) return "0";
  if (qps >= 1) return Math.round(qps).toString();
  return qps.toFixed(2);
}

function lineOption(x: string[], series: { name: string; data: number[] }[], unit?: string) {
  return {
    color: chartColors,
    grid: baseGrid,
    tooltip: { trigger: "axis", ...softTooltip },
    legend: { right: 0, top: 0, ...legendStyle },
    xAxis: { type: "category", boundaryGap: false, data: x, ...axisStyle },
    yAxis: {
      type: "value",
      ...axisStyle,
      axisLabel: unit ? { ...axisStyle.axisLabel, formatter: `{value}${unit}` } : axisStyle.axisLabel,
    },
    series: series.map((s) => ({
      name: s.name,
      type: "line",
      smooth: true,
      showSymbol: false,
      lineStyle: { width: 2.5 },
      data: s.data,
    })),
  };
}

function connStatusTone(status: string): Tone {
  if (status === "error") return "danger";
  if (status === "warning") return "warning";
  return "success";
}
function connStatusText(status: string, t: TFunction): string {
  if (status === "error") return t("monitoring.services.connError");
  if (status === "warning") return t("monitoring.services.connWarning");
  return t("monitoring.services.connActive");
}

function V2Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between rounded-control bg-surface-muted px-2 py-1 text-xs">
      <span className="text-muted">{label}</span>
      <span className="font-semibold text-ink tabular-nums">{value}</span>
    </div>
  );
}

function ServiceCard({ svc, t }: { svc: ServiceInfo; t: TFunction }) {
  const statusText = buildStatusText(t);
  const v2: { label: string; value: string }[] = [];
  if (svc.p99LatencyMs && svc.p99LatencyMs > 0) v2.push({ label: "p99", value: `${svc.p99LatencyMs.toFixed(1)}ms` });
  if (svc.errorRate && svc.errorRate > 0) v2.push({ label: t("monitoring.services.labelErrorRate"), value: `${(svc.errorRate * 100).toFixed(2)}%` });
  if (svc.connections && svc.connections > 0) v2.push({ label: t("monitoring.services.labelConnections"), value: String(svc.connections) });
  if (svc.queueLag && svc.queueLag > 0) v2.push({ label: t("monitoring.services.labelQueueLag"), value: String(svc.queueLag) });
  if (svc.goroutineCount && svc.goroutineCount > 0) v2.push({ label: "goroutine", value: String(svc.goroutineCount) });
  if (svc.gcPauseP99Ms && svc.gcPauseP99Ms > 0) v2.push({ label: "GC p99", value: `${svc.gcPauseP99Ms}ms` });

  return (
    <Card className="flex flex-col p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={cn("h-2 w-2 rounded-full", dotColor[svc.status])} />
          <span className="text-base font-semibold text-ink">{svc.name}</span>
        </div>
        <StatusTag tone={statusTone[svc.status]}>{statusText[svc.status]}</StatusTag>
      </div>
      <div className="mb-4 grid grid-cols-3 gap-3 text-center">
        <div>
          <div className="truncate text-xl font-semibold text-ink tabular-nums">{formatQps(svc.qps)}</div>
          <div className="mt-0.5 text-xs text-muted">QPS</div>
        </div>
        <div>
          <div className="truncate text-xl font-semibold text-ink tabular-nums">{svc.cpu}%</div>
          <div className="mt-0.5 text-xs text-muted">CPU</div>
        </div>
        <div>
          <div className="truncate text-xl font-semibold text-ink">{svc.memory}</div>
          <div className="mt-0.5 text-xs text-muted">{t("monitoring.services.memory")}</div>
        </div>
      </div>
      {v2.length > 0 && (
        <div className="mb-4 grid grid-cols-2 gap-2 border-t border-dashed border-border pt-3">
          {v2.map((m) => (
            <V2Row key={m.label} label={m.label} value={m.value} />
          ))}
        </div>
      )}
      <div className="mt-auto flex flex-wrap gap-x-4 gap-y-1 border-t border-border pt-3 text-xs text-muted">
        <span>{t("monitoring.services.labelPid")}: {svc.pid}</span>
        <span>{t("monitoring.services.labelUptime")}: {svc.uptime}</span>
        <span>{t("monitoring.services.labelVersion")}: {svc.version}</span>
      </div>
      {svc.detail && <div className="mt-2 break-all text-xs text-muted">{svc.detail}</div>}
    </Card>
  );
}

export default function ServiceMonitorPage() {
  const { t } = useTranslation();
  const rangeItems = buildRangeItems(t);
  const [range, setRange] = useState<MonitorRange>("1h");
  const { data } = useQuery({
    queryKey: ["mon-services", range],
    queryFn: () => monitorApi.serviceMetrics(range),
  });

  const services = data?.services ?? [];
  const qps = data?.qps ?? [];
  const latency = data?.latency ?? [];
  const connections = data?.connections ?? [];

  const qpsKeys = Array.from(
    new Set(qps.flatMap((p) => Object.keys(p).filter((k) => k !== "time"))),
  );

  const connColumns: Column<ServiceConnection>[] = [
    { key: "service", title: t("monitoring.services.colService"), render: (r) => <span className="font-medium text-ink">{r.service}</span> },
    { key: "protocol", title: t("monitoring.services.colProtocol"), render: (r) => <span className="text-muted">{r.protocol}</span> },
    { key: "address", title: t("monitoring.services.colAddress"), render: (r) => <span className="font-mono text-xs text-muted">{r.address}</span> },
    { key: "activeConnections", title: t("monitoring.services.colActiveConnections"), render: (r) => <span className="text-ink tabular-nums">{r.activeConnections}</span> },
    { key: "totalConnections", title: t("monitoring.services.colTotalConnections"), render: (r) => <span className="text-muted tabular-nums">{r.totalConnections}</span> },
    { key: "status", title: t("common.status"), render: (r) => <StatusTag tone={connStatusTone(r.status)}>{connStatusText(r.status, t)}</StatusTag> },
  ];

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Tabs items={rangeItems} active={range} onChange={(k) => setRange(k as MonitorRange)} />
      </div>

      {services.length === 0 ? (
        <Card>
          <EmptyState title={t("monitoring.services.emptyServices")} desc="" />
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-3">
          {services.map((svc, i) => (
            <ServiceCard key={`${svc.name}-${i}`} svc={svc} t={t} />
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard
          title={t("monitoring.services.chartQps")}
          option={lineOption(
            qps.map((d) => d.time),
            qpsKeys.map((k) => ({ name: k, data: qps.map((d) => Number(d[k] ?? 0)) })),
          )}
        />
        <ChartCard
          title={t("monitoring.services.chartLatency")}
          option={lineOption(
            latency.map((d) => d.time),
            [
              { name: "P50", data: latency.map((d) => d.p50) },
              { name: "P95", data: latency.map((d) => d.p95) },
              { name: "P99", data: latency.map((d) => d.p99) },
            ],
            " ms",
          )}
        />
      </div>

      <Card>
        <DataTable
          columns={connColumns}
          rows={connections}
          rowKey={(r) => `${r.service}-${r.address}`}
          emptyText={t("monitoring.services.emptyConnections")}
        />
      </Card>
    </div>
  );
}
