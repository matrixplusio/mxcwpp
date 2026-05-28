import { computed } from 'vue'
import { useThemeStore } from '@/stores/theme'

/**
 * ECharts 主题 token — 响应浅色/暗色切换
 */
export function useChartTheme() {
  const themeStore = useThemeStore()

  const chartTheme = computed(() => {
    if (themeStore.isDark) {
      return {
        tooltipBg: '#1C2333',
        tooltipBorder: 'rgba(30, 58, 95, 0.3)',
        tooltipText: '#E5E5E5',
        gridLine: 'rgba(30, 58, 95, 0.2)',
        axisLabel: '#888888',
        axisLine: 'rgba(30, 58, 95, 0.3)',
        legendText: '#AAAAAA',
      }
    }
    return {
      tooltipBg: '#FFFFFF',
      tooltipBorder: '#E5E8EF',
      tooltipText: '#1D2129',
      gridLine: '#F2F3F5',
      axisLabel: '#86909C',
      axisLine: '#E5E8EF',
      legendText: '#4E5969',
    }
  })

  return { chartTheme }
}
