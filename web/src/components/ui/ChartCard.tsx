"use client";
import ReactECharts from "echarts-for-react";
import { Card, CardHeader } from "./Card";
import { useThemeStore } from "@/stores/theme";
import { chartTheme } from "@/lib/echartsTheme";

/** 深合并:仅覆盖 option 中已显式设置的浅色值(tooltip/axisLabel/splitLine/textStyle) */
function applyDarkOverrides(option: Record<string, unknown>): Record<string, unknown> {
  const t = chartTheme(true);
  const next: Record<string, unknown> = { ...option };

  // 全局文字色
  next.textStyle = { ...(option.textStyle as object), color: "#E2E8F0" };

  // tooltip 背景/边框/文字
  if (option.tooltip && typeof option.tooltip === "object" && !Array.isArray(option.tooltip)) {
    next.tooltip = {
      ...(option.tooltip as object),
      backgroundColor: t.softTooltip.backgroundColor,
      borderColor: t.softTooltip.borderColor,
      textStyle: { ...((option.tooltip as Record<string, unknown>).textStyle as object), color: "#E2E8F0" },
    };
  }

  // 坐标轴 splitLine 颜色(数组或单对象)
  const fixAxis = (axis: unknown): unknown => {
    if (!axis) return axis;
    const arr = Array.isArray(axis) ? axis : [axis];
    const mapped = arr.map((a) => {
      const ax = a as Record<string, unknown>;
      if (!ax.splitLine || typeof ax.splitLine !== "object") return ax;
      const sl = ax.splitLine as Record<string, unknown>;
      return { ...ax, splitLine: { ...sl, lineStyle: { ...(sl.lineStyle as object), color: t.splitLineColor } } };
    });
    return Array.isArray(axis) ? mapped : mapped[0];
  };
  if (option.xAxis) next.xAxis = fixAxis(option.xAxis);
  if (option.yAxis) next.yAxis = fixAxis(option.yAxis);

  return next;
}

export function ChartCard({ title, option, height = 260, extra }: { title: string; option: object; height?: number; extra?: React.ReactNode }) {
  const mode = useThemeStore((s) => s.mode);
  const finalOption = mode === "dark" ? applyDarkOverrides(option as Record<string, unknown>) : option;
  return (
    <Card>
      <CardHeader title={title} extra={extra} />
      <div className="px-3 pb-4">
        <ReactECharts key={mode} option={finalOption} style={{ height }} notMerge lazyUpdate />
      </div>
    </Card>
  );
}
