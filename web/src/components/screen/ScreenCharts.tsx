"use client";
import ReactECharts from "echarts-for-react";

const SEV = { critical: "#f43f5e", high: "#fb923c", medium: "#facc15", low: "#38bdf8" };

/** 态势总分仪表盘（0-100，越高越安全）。 */
export function PostureGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#34d399" : score >= 60 ? "#facc15" : "#f43f5e";
  const option = {
    series: [
      {
        type: "gauge",
        startAngle: 215,
        endAngle: -35,
        min: 0,
        max: 100,
        radius: "88%",
        progress: { show: true, width: 12, roundCap: true, itemStyle: { color, shadowBlur: 12, shadowColor: color } },
        axisLine: { lineStyle: { width: 12, color: [[1, "rgba(148,163,184,0.12)"]] } },
        axisTick: { show: false },
        splitLine: { distance: -12, length: 12, lineStyle: { color: "rgba(148,163,184,0.18)", width: 1 } },
        axisLabel: { show: false },
        pointer: { show: false },
        anchor: { show: false },
        detail: {
          valueAnimation: true,
          offsetCenter: [0, "-8%"],
          fontSize: 50,
          fontWeight: 800,
          color,
          formatter: "{value}",
        },
        title: { offsetCenter: [0, "46%"], fontSize: 12, color: "#64748b" },
        data: [{ value: score, name: "综合评分 / 100" }],
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: "100%", width: "100%" }} notMerge lazyUpdate />;
}

/** 告警 severity 环形分布。 */
export function SeverityRing({ d }: { d: { critical: number; high: number; medium: number; low: number } }) {
  const total = d.critical + d.high + d.medium + d.low;
  const option = {
    color: [SEV.critical, SEV.high, SEV.medium, SEV.low],
    tooltip: { trigger: "item", backgroundColor: "#0b1424", borderColor: "rgba(34,211,238,0.3)", textStyle: { color: "#e2e8f0" } },
    legend: {
      bottom: 0,
      textStyle: { color: "#94a3b8", fontSize: 11 },
      itemWidth: 10,
      itemHeight: 10,
    },
    series: [
      {
        type: "pie",
        radius: ["58%", "80%"],
        center: ["50%", "44%"],
        avoidLabelOverlap: false,
        itemStyle: { borderColor: "#070D1B", borderWidth: 3 },
        label: {
          show: true,
          position: "center",
          formatter: `{a|${total}}\n{b|活跃告警}`,
          rich: {
            a: { fontSize: 30, fontWeight: 800, color: "#e2e8f0" },
            b: { fontSize: 11, color: "#64748b", padding: [4, 0, 0, 0] },
          },
        },
        labelLine: { show: false },
        data: [
          { name: "严重", value: d.critical },
          { name: "高危", value: d.high },
          { name: "中危", value: d.medium },
          { name: "低危", value: d.low },
        ],
      },
    ],
  };
  return <ReactECharts option={option} style={{ height: "100%", width: "100%" }} notMerge lazyUpdate />;
}

/** 24h 多引擎告警趋势叠加。 */
export function TrendChart({
  hours,
  edr,
  bde,
  ml,
}: {
  hours: string[];
  edr: number[];
  bde: number[];
  ml: number[];
}) {
  const area = (from: string) => ({
    type: "line" as const,
    smooth: true,
    symbol: "none",
    lineStyle: { width: 2 },
    areaStyle: { opacity: 0.15 },
    emphasis: { focus: "series" as const },
  });
  const option = {
    color: ["#22d3ee", "#a78bfa", "#fb923c"],
    tooltip: { trigger: "axis", backgroundColor: "#0b1424", borderColor: "rgba(34,211,238,0.3)", textStyle: { color: "#e2e8f0" } },
    legend: { top: 0, right: 0, textStyle: { color: "#94a3b8", fontSize: 11 }, icon: "roundRect", itemWidth: 12, itemHeight: 6 },
    grid: { left: 36, right: 12, top: 28, bottom: 22 },
    xAxis: {
      type: "category",
      data: hours,
      axisLine: { lineStyle: { color: "rgba(148,163,184,0.25)" } },
      axisLabel: { color: "#64748b", fontSize: 10 },
    },
    yAxis: {
      type: "value",
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.08)" } },
      axisLabel: { color: "#64748b", fontSize: 10 },
    },
    series: [
      { name: "EDR", data: edr, ...area("#22d3ee") },
      { name: "行为", data: bde, ...area("#a78bfa") },
      { name: "ML", data: ml, ...area("#fb923c") },
    ],
  };
  return <ReactECharts option={option} style={{ height: "100%", width: "100%" }} notMerge lazyUpdate />;
}
