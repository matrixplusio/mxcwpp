<template>
  <div class="asset-history-panel">
    <div class="toolbar">
      <div class="toolbar-title">
        <span class="title-text">{{ title }}</span>
        <span class="title-meta">
          {{ history?.scope === 'host' ? '当前主机' : '当前范围' }} · {{ history?.total_snapshots ?? 0 }} 个快照
        </span>
      </div>

      <a-radio-group v-model:value="days" size="small" @change="loadHistory">
        <a-radio-button :value="1">1天</a-radio-button>
        <a-radio-button :value="7">7天</a-radio-button>
        <a-radio-button :value="30">30天</a-radio-button>
      </a-radio-group>
    </div>

    <a-spin :spinning="loading">
      <template v-if="history && history.points.length > 0">
        <div class="summary-row">
          <div class="summary-card">
            <div class="summary-label">最新快照</div>
            <div class="summary-value">{{ latestPoint?.total ?? 0 }}</div>
            <div class="summary-hint">最近采集 {{ history.latest_collected_at }}</div>
          </div>
          <div class="summary-card">
            <div class="summary-label">快照变化</div>
            <div class="summary-value" :class="{ positive: (latestPoint?.delta_total ?? 0) >= 0, negative: (latestPoint?.delta_total ?? 0) < 0 }">
              {{ formatDelta(latestPoint?.delta_total ?? 0) }}
            </div>
            <div class="summary-hint">相对上一快照的资产数量变化</div>
          </div>
          <div class="summary-card">
            <div class="summary-label">趋势窗口</div>
            <div class="summary-value">{{ history.points.length }}</div>
            <div class="summary-hint">当前窗口内有效采集快照数</div>
          </div>
        </div>

        <div class="chart-card">
          <v-chart :option="chartOption" autoresize style="height: 280px" />
        </div>

        <div class="snapshot-list">
          <div v-for="point in recentPoints" :key="point.timestamp" class="snapshot-card">
            <div class="snapshot-header">
              <div class="snapshot-time">{{ point.timestamp }}</div>
              <a-tag :color="point.delta_total >= 0 ? 'green' : 'red'">{{ formatDelta(point.delta_total) }}</a-tag>
            </div>

            <div class="snapshot-total">{{ point.total }}</div>
            <div class="snapshot-total-label">总资产数</div>

            <div class="snapshot-metrics">
              <span>进程 {{ point.statistics.processes }}</span>
              <span>端口 {{ point.statistics.ports }}</span>
              <span>软件 {{ point.statistics.software }}</span>
              <span>应用 {{ point.statistics.apps }}</span>
              <span>服务 {{ point.statistics.services }}</span>
            </div>
          </div>
        </div>
      </template>

      <a-empty v-else description="当前范围暂无资产历史快照" />
    </a-spin>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import type { EChartsOption } from 'echarts'
import { assetsApi } from '@/api/assets'
import type { AssetHistoryResult } from '@/api/types'

const props = withDefaults(defineProps<{
  hostId?: string
  businessLine?: string
  title?: string
}>(), {
  hostId: undefined,
  businessLine: undefined,
  title: '资产历史',
})

const loading = ref(false)
const days = ref(7)
const history = ref<AssetHistoryResult>()

const latestPoint = computed(() => {
  const points = history.value?.points ?? []
  return points.length > 0 ? points[points.length - 1] : undefined
})

const recentPoints = computed(() => {
  const points = history.value?.points ?? []
  return [...points].reverse().slice(0, 6)
})

const chartOption = computed<EChartsOption>(() => {
  const points = history.value?.points ?? []
  return {
    grid: { left: 24, right: 24, top: 32, bottom: 28 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: points.map(point => point.timestamp.slice(5)),
      axisLabel: { color: '#86909C' },
      axisLine: { lineStyle: { color: '#E5E8EF' } },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#86909C' },
      splitLine: { lineStyle: { color: '#F2F3F5' } },
    },
    series: [
      {
        type: 'line',
        smooth: true,
        symbolSize: 8,
        data: points.map(point => point.total),
        lineStyle: { color: '#165DFF', width: 3 },
        itemStyle: { color: '#165DFF' },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(22, 93, 255, 0.24)' },
              { offset: 1, color: 'rgba(22, 93, 255, 0.02)' },
            ],
          },
        },
      },
    ],
  }
})

const formatDelta = (value: number) => {
  if (value > 0) return `+${value}`
  return `${value}`
}

const loadHistory = async () => {
  loading.value = true
  try {
    history.value = await assetsApi.getHistory({
      host_id: props.hostId || undefined,
      business_line: props.businessLine || undefined,
      days: days.value,
      limit: 20,
    })
  } catch {
    history.value = undefined
  } finally {
    loading.value = false
  }
}

watch(
  () => [props.hostId, props.businessLine],
  () => {
    loadHistory()
  }
)

onMounted(() => {
  loadHistory()
})
</script>

<style scoped>
.asset-history-panel {
  width: 100%;
}

.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
}

.toolbar-title {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.title-text {
  font-size: 14px;
  font-weight: 700;
  color: #1D2129;
}

.title-meta {
  font-size: 12px;
  color: #86909C;
}

.summary-row {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.summary-card {
  padding: 16px;
  border: 1px solid #E5E8EF;
  border-radius: 10px;
  background: #FFFFFF;
}

.summary-label {
  font-size: 12px;
  color: #86909C;
}

.summary-value {
  margin-top: 8px;
  font-size: 28px;
  line-height: 1.1;
  font-weight: 700;
  color: #1D2129;
}

.summary-value.positive {
  color: #00B42A;
}

.summary-value.negative {
  color: #F53F3F;
}

.summary-hint {
  margin-top: 8px;
  font-size: 12px;
  color: #4E5969;
}

.chart-card {
  margin-bottom: 16px;
  padding: 12px;
  border: 1px solid #E5E8EF;
  border-radius: 10px;
  background: #FFFFFF;
}

.snapshot-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 12px;
}

.snapshot-card {
  padding: 14px;
  border: 1px solid #E5E8EF;
  border-radius: 10px;
  background: linear-gradient(180deg, #FFFFFF 0%, #FAFBFD 100%);
}

.snapshot-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.snapshot-time {
  font-size: 12px;
  color: #4E5969;
}

.snapshot-total {
  margin-top: 12px;
  font-size: 30px;
  line-height: 1;
  font-weight: 700;
  color: #1D2129;
}

.snapshot-total-label {
  margin-top: 6px;
  font-size: 12px;
  color: #86909C;
}

.snapshot-metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 12px;
  font-size: 12px;
  color: #4E5969;
}
</style>
