"use client";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { Cpu, MemoryStick, HardDrive, Gauge, Activity, Boxes } from "lucide-react";
import { monitorApi } from "@/lib/api/monitoring";
import type { HostDiskPartition, MonitorRange } from "@/lib/api/types";
import { Card } from "@/components/ui/Card";
import { StatCard } from "@/components/ui/StatCard";
import { ChartCard } from "@/components/ui/ChartCard";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { StatusTag } from "@/components/ui/Tag";
import { Tabs } from "@/components/ui/Tabs";
import { chartColors, baseGrid, axisStyle, softTooltip, legendStyle } from "@/lib/echartsTheme";

const buildRangeItems = (t: TFunction) => [
  { key: "1h", label: t("monitoring.range.1h") },
  { key: "6h", label: t("monitoring.range.6h") },
  { key: "24h", label: t("monitoring.range.24h") },
];

type Tone = "default" | "danger" | "warning" | "success";
function pctTone(v: number): Tone {
  if (v > 90) return "danger";
  if (v > 70) return "warning";
  return "success";
}

function lineOption(
  x: string[],
  series: { name: string; data: number[] }[],
  unit?: string,
) {
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
      areaStyle: { opacity: 0.05 },
      data: s.data,
    })),
  };
}

function partitionTone(v: number): "danger" | "warning" | "success" {
  if (v > 90) return "danger";
  if (v > 70) return "warning";
  return "success";
}
function partitionText(v: number, t: TFunction): string {
  if (v > 90) return t("monitoring.host.partAlert");
  if (v > 70) return t("monitoring.host.partNotice");
  return t("monitoring.host.partNormal");
}

export default function HostMonitorPage() {
  const { t } = useTranslation();
  const rangeItems = buildRangeItems(t);
  const [range, setRange] = useState<MonitorRange>("1h");
  const { data, isLoading, isError } = useQuery({
    queryKey: ["mon-host", range],
    queryFn: () => monitorApi.hostMetrics(range),
  });
  // 取不到就明说取不到：`?? 0` 会把"后端没答上来"渲染成 0，
  // 看板上读起来像"环境干净"。
  const statState = { error: isError, loading: isLoading };

  const ov = data?.overview;
  const cpu = data?.cpu ?? [];
  const memory = data?.memory ?? [];
  const disk = data?.disk ?? [];
  const network = data?.network ?? [];
  const partitions = data?.partitions ?? [];

  const partColumns: Column<HostDiskPartition>[] = [
    { key: "mountPoint", title: t("monitoring.host.colMountPoint"), render: (r) => <span className="font-medium text-ink">{r.mountPoint}</span> },
    { key: "filesystem", title: t("monitoring.host.colFilesystem"), render: (r) => <span className="text-muted">{r.filesystem}</span> },
    { key: "total", title: t("monitoring.host.colTotal"), render: (r) => <span className="text-muted tabular-nums">{r.total}</span> },
    { key: "used", title: t("monitoring.host.colUsed"), render: (r) => <span className="text-muted tabular-nums">{r.used}</span> },
    { key: "available", title: t("monitoring.host.colAvailable"), render: (r) => <span className="text-muted tabular-nums">{r.available}</span> },
    {
      key: "usagePercent",
      title: t("monitoring.host.colUsage"),
      render: (r) => <span className="text-ink tabular-nums">{r.usagePercent.toFixed(1)}%</span>,
    },
    {
      key: "status",
      title: t("common.status"),
      render: (r) => <StatusTag tone={partitionTone(r.usagePercent)}>{partitionText(r.usagePercent, t)}</StatusTag>,
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Tabs items={rangeItems} active={range} onChange={(k) => setRange(k as MonitorRange)} />
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <StatCard label={t("monitoring.host.statCpu")} value={`${(ov?.cpu ?? 0).toFixed(1)}%`} {...statState} icon={Cpu} tone={pctTone(ov?.cpu ?? 0)} />
        <StatCard label={t("monitoring.host.statMemory")} value={`${(ov?.memory ?? 0).toFixed(1)}%`} {...statState} icon={MemoryStick} tone={pctTone(ov?.memory ?? 0)} />
        <StatCard label={t("monitoring.host.statDisk")} value={`${(ov?.disk ?? 0).toFixed(1)}%`} {...statState} icon={HardDrive} tone={pctTone(ov?.disk ?? 0)} />
        <StatCard label={t("monitoring.host.statLoad")} value={(ov?.load ?? 0).toFixed(2)} {...statState} icon={Gauge} tone="default" />
        <StatCard label={t("monitoring.host.statAgentCpu")} value={`${(ov?.agentCpu ?? 0).toFixed(1)}%`} {...statState} icon={Activity} tone={pctTone(ov?.agentCpu ?? 0)} />
        <StatCard label={t("monitoring.host.statAgentMem")} value={`${(ov?.agentMemMB ?? 0).toFixed(1)} MB`} {...statState} icon={Boxes} tone="default" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ChartCard
          title={t("monitoring.host.chartCpu")}
          option={lineOption(cpu.map((d) => d.time), [{ name: t("monitoring.host.seriesCpu"), data: cpu.map((d) => d.usage) }], "%")}
        />
        <ChartCard
          title={t("monitoring.host.chartMemory")}
          option={lineOption(memory.map((d) => d.time), [{ name: t("monitoring.host.seriesMemory"), data: memory.map((d) => d.usage) }], "%")}
        />
        <ChartCard
          title={t("monitoring.host.chartDiskIo")}
          option={lineOption(disk.map((d) => d.time), [
            { name: t("monitoring.host.seriesRead"), data: disk.map((d) => d.read) },
            { name: t("monitoring.host.seriesWrite"), data: disk.map((d) => d.write) },
          ])}
        />
        <ChartCard
          title={t("monitoring.host.chartNetwork")}
          option={lineOption(network.map((d) => d.time), [
            { name: t("monitoring.host.seriesInbound"), data: network.map((d) => d.inbound) },
            { name: t("monitoring.host.seriesOutbound"), data: network.map((d) => d.outbound) },
          ])}
        />
      </div>

      <Card>
        <DataTable
          columns={partColumns}
          rows={partitions}
          rowKey={(r) => r.mountPoint}
          loading={isLoading}
          emptyText={t("monitoring.host.emptyPartitions")}
        />
      </Card>
    </div>
  );
}
