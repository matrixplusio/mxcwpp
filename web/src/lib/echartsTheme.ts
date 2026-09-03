export const chartColors = ["#2563EB", "#4F7DF9", "#0EA5E9", "#F59E0B", "#E5484D"];

/** 告警级别统一配色，顺序 [严重, 高危, 中危, 低危]，与 SeverityTag/环形图一致 */
export const severityColors = ["#E5484D", "#F59E0B", "#2563EB", "#94A3B8"];

export const baseGrid = { left: 8, right: 16, top: 28, bottom: 8, containLabel: true };

export const axisStyle = {
  axisLine: { show: false },
  axisTick: { show: false },
  axisLabel: { color: "#94A3B8", fontSize: 12 },
  splitLine: { lineStyle: { color: "#F1F4F8", type: "dashed" as const } },
};

export const softTooltip = {
  backgroundColor: "#FFFFFF",
  borderColor: "#E9EDF3",
  borderWidth: 1,
  padding: [8, 12],
  textStyle: { color: "#0F172A", fontSize: 12 },
  extraCssText: "box-shadow: 0 8px 24px -12px rgba(15,23,42,0.18); border-radius: 10px;",
};

export const legendStyle = {
  icon: "roundRect" as const,
  itemWidth: 8,
  itemHeight: 8,
  itemGap: 14,
  textStyle: { color: "#64748B", fontSize: 12 },
};

/**
 * 主题感知配置。ECharts 不能用 CSS 变量,故按明暗返回对应色值。
 * ChartCard 取 darkOverrides 深合并到 option,使页面静态 option 在深色下也可读。
 */
export function chartTheme(dark: boolean) {
  const splitLineColor = dark ? "#1E2636" : "#F1F4F8";
  return {
    axisStyle: {
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: "#94A3B8", fontSize: 12 },
      splitLine: { lineStyle: { color: splitLineColor, type: "dashed" as const } },
    },
    softTooltip: {
      backgroundColor: dark ? "#131927" : "#FFFFFF",
      borderColor: dark ? "#2E3850" : "#E9EDF3",
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: dark ? "#E2E8F0" : "#0F172A", fontSize: 12 },
      extraCssText: "box-shadow: 0 8px 24px -12px rgba(15,23,42,0.18); border-radius: 10px;",
    },
    legendStyle: {
      icon: "roundRect" as const,
      itemWidth: 8,
      itemHeight: 8,
      itemGap: 14,
      textStyle: { color: dark ? "#94A3B8" : "#64748B", fontSize: 12 },
    },
    splitLineColor,
  };
}
