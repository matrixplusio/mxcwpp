// 矩阵云安全平台 - ECharts 全局主题 'mxsec'
//
// 注册后所有 VChart / echarts.init 用 'mxsec' 主题，统一配色 / 字体 / 圆角 / 间距。
// 与 styles/tokens.scss 保持视觉一致。
//
// 用法:
//   1. main.ts 入口 import 'utils/echartsTheme' 自动注册
//   2. <VChart :option="opt" theme="mxsec" />
//      或 echarts.init(dom, 'mxsec')

import * as echarts from 'echarts/core'

const MXSEC_PALETTE = [
  '#3B82F6', // 蓝
  '#22C55E', // 绿
  '#F59E0B', // 橙
  '#EF4444', // 红
  '#722ed1', // 紫
  '#14b8a6', // 青
  '#ec4899', // 粉
  '#6366f1', // 靛
]

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#0891b2',
  info: '#6366f1',
}

echarts.registerTheme('mxsec', {
  color: MXSEC_PALETTE,
  backgroundColor: 'transparent',
  textStyle: {
    fontFamily: 'PingFang SC, Microsoft YaHei, Inter, -apple-system, sans-serif',
    fontSize: 12,
    color: 'rgba(0, 0, 0, 0.85)',
  },
  title: {
    textStyle: {
      color: 'rgba(0, 0, 0, 0.88)',
      fontSize: 16,
      fontWeight: 600,
    },
    subtextStyle: {
      color: 'rgba(0, 0, 0, 0.45)',
      fontSize: 12,
    },
  },
  legend: {
    textStyle: {
      color: 'rgba(0, 0, 0, 0.65)',
      fontSize: 12,
    },
    itemGap: 16,
  },
  tooltip: {
    backgroundColor: 'rgba(31, 41, 55, 0.95)',
    borderColor: 'transparent',
    borderRadius: 8,
    textStyle: {
      color: '#fff',
      fontSize: 12,
    },
    extraCssText: 'box-shadow: 0 4px 6px rgba(0,0,0,0.1);',
  },
  grid: {
    left: '3%',
    right: '4%',
    bottom: '8%',
    top: '12%',
    containLabel: true,
  },
  xAxis: {
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisTick: { lineStyle: { color: '#e5e7eb' } },
    axisLabel: { color: 'rgba(0, 0, 0, 0.65)', fontSize: 11 },
    splitLine: { lineStyle: { color: '#f3f4f6' } },
  },
  yAxis: {
    axisLine: { lineStyle: { color: '#e5e7eb' } },
    axisTick: { lineStyle: { color: '#e5e7eb' } },
    axisLabel: { color: 'rgba(0, 0, 0, 0.65)', fontSize: 11 },
    splitLine: { lineStyle: { color: '#f3f4f6' } },
  },
  bar: {
    itemStyle: {
      borderRadius: [4, 4, 0, 0],
    },
  },
  line: {
    lineStyle: { width: 2 },
    symbolSize: 6,
    smooth: true,
  },
  pie: {
    itemStyle: {
      borderRadius: 6,
      borderColor: '#fff',
      borderWidth: 2,
    },
    label: {
      color: 'rgba(0, 0, 0, 0.85)',
    },
  },
})

export const mxsecPalette = MXSEC_PALETTE
export const severityColors = SEVERITY_COLORS

/**
 * severityPieData 帮助函数：给定 {critical, high, medium, low} 计数返回
 * pie chart 所需 series.data，自动套上对应配色 + label。
 */
export function severityPieData(dist: Partial<Record<keyof typeof SEVERITY_COLORS, number>>) {
  const labels: Record<keyof typeof SEVERITY_COLORS, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '提示',
  }
  return (Object.keys(SEVERITY_COLORS) as Array<keyof typeof SEVERITY_COLORS>)
    .map((sev) => ({
      value: dist[sev] || 0,
      name: labels[sev],
      itemStyle: { color: SEVERITY_COLORS[sev] },
    }))
    .filter((it) => it.value > 0)
}
