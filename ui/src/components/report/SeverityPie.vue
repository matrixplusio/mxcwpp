<template>
  <VChart :option="option" :theme="theme" :style="{ height: `${height}px` }" autoresize />
</template>

<script setup lang="ts">
import { computed } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import type { EChartsOption } from 'echarts'
import { severityPieData } from '@/utils/echartsTheme'

use([CanvasRenderer, PieChart, TitleComponent, TooltipComponent, LegendComponent])

interface Props {
  distribution: { critical?: number; high?: number; medium?: number; low?: number; info?: number }
  title?: string
  height?: number
  showLegend?: boolean
  theme?: string
}
const props = withDefaults(defineProps<Props>(), {
  title: '',
  height: 280,
  showLegend: true,
  theme: 'mxsec',
})

const option = computed<EChartsOption>(() => ({
  title: props.title ? { text: props.title, left: 'center', top: 8 } : undefined,
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: props.showLegend ? { orient: 'vertical', left: 'left', top: 'middle' } : undefined,
  series: [
    {
      type: 'pie',
      radius: ['42%', '70%'],
      avoidLabelOverlap: true,
      label: { show: false },
      labelLine: { show: false },
      data: severityPieData(props.distribution),
    },
  ],
}))
</script>
