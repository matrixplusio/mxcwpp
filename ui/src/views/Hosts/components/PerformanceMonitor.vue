<template>
  <div class="performance-monitor">
    <a-spin :spinning="loading">
      <div v-if="!loading">
        <!-- 时间范围 + 数据源信息栏 -->
        <div class="top-bar">
          <a-radio-group v-model:value="rangeParam" button-style="solid" size="small" @change="onRangeChange">
            <a-radio-button value="1h">近1小时</a-radio-button>
            <a-radio-button value="6h">近6小时</a-radio-button>
            <a-radio-button value="24h">近24小时</a-radio-button>
          </a-radio-group>
          <div class="source-info" v-if="metrics?.source">
            <span class="source-tag">{{ sourceLabel }}</span>
            <span class="source-time" v-if="metrics.latest?.collected_at">
              <ClockCircleOutlined style="margin-right: 4px;" />
              {{ formatTime(metrics.latest.collected_at) }}
            </span>
          </div>
        </div>

        <a-alert
          v-if="errorMessage"
          class="state-alert"
          type="error"
          show-icon
          :message="errorMessage"
        />

        <template v-else-if="hasMetricsData">
          <!-- 指标卡片行 -->
          <div class="metrics-row" v-if="metrics?.latest">
            <div class="metric-card">
              <div class="metric-icon-bg cpu-bg"><DashboardOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">CPU 使用率</div>
                <div class="metric-value" :style="{ color: getUsageColor(metrics.latest.cpu_usage) }">
                  {{ metrics.latest.cpu_usage?.toFixed(1) ?? '-' }}<span class="metric-unit">%</span>
                </div>
                <a-progress :percent="metrics.latest.cpu_usage || 0" :show-info="false"
                  :stroke-color="getUsageColor(metrics.latest.cpu_usage)" :stroke-width="4" size="small" />
              </div>
            </div>
            <div class="metric-card">
              <div class="metric-icon-bg mem-bg"><DatabaseOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">内存使用率</div>
                <div class="metric-value" :style="{ color: getUsageColor(metrics.latest.mem_usage) }">
                  {{ metrics.latest.mem_usage?.toFixed(1) ?? '-' }}<span class="metric-unit">%</span>
                </div>
                <a-progress :percent="metrics.latest.mem_usage || 0" :show-info="false"
                  :stroke-color="getUsageColor(metrics.latest.mem_usage)" :stroke-width="4" size="small" />
              </div>
            </div>
            <div class="metric-card">
              <div class="metric-icon-bg disk-bg"><HddOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">磁盘使用率</div>
                <div class="metric-value" :style="{ color: getUsageColor(metrics.latest.disk_usage) }">
                  {{ metrics.latest.disk_usage?.toFixed(1) ?? '-' }}<span class="metric-unit">%</span>
                </div>
                <a-progress :percent="metrics.latest.disk_usage || 0" :show-info="false"
                  :stroke-color="getUsageColor(metrics.latest.disk_usage)" :stroke-width="4" size="small" />
              </div>
            </div>
            <div class="metric-card">
              <div class="metric-icon-bg net-send-bg"><SwapOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">网络 发送 / 接收</div>
                <div class="metric-value net">
                  {{ formatBytes(metrics.latest.net_bytes_sent || 0) }}
                  <span class="metric-sep">/</span>
                  {{ formatBytes(metrics.latest.net_bytes_recv || 0) }}
                </div>
              </div>
            </div>
            <div class="metric-card">
              <div class="metric-icon-bg io-bg"><ThunderboltOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">磁盘 I/O 读 / 写</div>
                <div class="metric-value net">
                  {{ formatBytes(metrics.latest.disk_read_bytes || 0) }}
                  <span class="metric-sep">/</span>
                  {{ formatBytes(metrics.latest.disk_write_bytes || 0) }}
                </div>
              </div>
            </div>
          </div>

          <!-- Agent 资源占用 -->
          <div class="metrics-row" v-if="metrics?.latest && (metrics.latest.agent_cpu_usage != null || metrics.latest.agent_mem_rss != null)">
            <div class="metric-card">
              <div class="metric-icon-bg agent-cpu-bg"><RobotOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">Agent CPU</div>
                <div class="metric-value" :style="{ color: getAgentCpuColor(metrics.latest.agent_cpu_usage) }">
                  {{ metrics.latest.agent_cpu_usage?.toFixed(1) ?? '-' }}<span class="metric-unit">%</span>
                </div>
                <a-progress :percent="metrics.latest.agent_cpu_usage || 0" :show-info="false"
                  :stroke-color="getAgentCpuColor(metrics.latest.agent_cpu_usage)" :stroke-width="4" size="small" />
              </div>
            </div>
            <div class="metric-card">
              <div class="metric-icon-bg agent-mem-bg"><RobotOutlined /></div>
              <div class="metric-info">
                <div class="metric-label">Agent 内存</div>
                <div class="metric-value" :style="{ color: getUsageColor(metrics.latest.agent_mem_percent) }">
                  {{ metrics.latest.agent_mem_percent?.toFixed(1) ?? '-' }}<span class="metric-unit">%</span>
                </div>
                <div style="font-size: 12px; color: #86909C; margin-top: 2px;">
                  RSS: {{ formatBytes(metrics.latest.agent_mem_rss || 0) }}
                </div>
              </div>
            </div>
          </div>

          <!-- 图表区域 -->
          <div class="charts-grid" v-if="metrics?.time_series">
            <!-- CPU 趋势 -->
            <div class="chart-card" v-if="cpuOption">
              <div class="chart-title">CPU 使用率趋势</div>
              <v-chart class="chart" :option="cpuOption" autoresize />
            </div>
            <!-- 内存趋势 -->
            <div class="chart-card" v-if="memOption">
              <div class="chart-title">内存使用率趋势</div>
              <v-chart class="chart" :option="memOption" autoresize />
            </div>
            <!-- 网络 I/O -->
            <div class="chart-card" v-if="netOption">
              <div class="chart-title">网络 I/O</div>
              <v-chart class="chart" :option="netOption" autoresize />
            </div>
            <!-- 磁盘 I/O -->
            <div class="chart-card" v-if="diskIOOption">
              <div class="chart-title">磁盘 I/O</div>
              <v-chart class="chart" :option="diskIOOption" autoresize />
            </div>
            <!-- Agent CPU 趋势 -->
            <div class="chart-card" v-if="agentCpuOption">
              <div class="chart-title">Agent CPU 使用率趋势</div>
              <v-chart class="chart" :option="agentCpuOption" autoresize />
            </div>
            <!-- Agent 内存趋势 -->
            <div class="chart-card" v-if="agentMemOption">
              <div class="chart-title">Agent 内存趋势</div>
              <v-chart class="chart" :option="agentMemOption" autoresize />
            </div>
          </div>
        </template>

        <a-empty v-else description="暂无监控数据" />
      </div>
    </a-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  DashboardOutlined,
  DatabaseOutlined,
  HddOutlined,
  SwapOutlined,
  ThunderboltOutlined,
  ClockCircleOutlined,
  RobotOutlined,
} from '@ant-design/icons-vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart } from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  GridComponent,
  LegendComponent,
} from 'echarts/components'
import { hostsApi } from '@/api/hosts'
import type { HostMetrics, TimeSeriesPoint } from '@/api/types'

use([CanvasRenderer, LineChart, TitleComponent, TooltipComponent, GridComponent, LegendComponent])

const props = defineProps<{ hostId: string }>()

const loading = ref(false)
const metrics = ref<HostMetrics | null>(null)
const errorMessage = ref('')
const rangeParam = ref<'1h' | '6h' | '24h'>('1h')
let refreshTimer: ReturnType<typeof setInterval> | null = null

const sourceLabel = computed(() => {
  const map: Record<string, string> = { prometheus: 'Prometheus' }
  return map[metrics.value?.source || ''] || metrics.value?.source || '-'
})

const hasMetricsData = computed(() => {
  const current = metrics.value
  if (!current) return false

  const hasLatest = Boolean(current.latest)
  const ts = current.time_series
  const hasSeries = Boolean(
    ts?.cpu_usage?.length ||
    ts?.mem_usage?.length ||
    ts?.disk_usage?.length ||
    ts?.net_in?.length ||
    ts?.net_out?.length ||
    ts?.disk_read?.length ||
    ts?.disk_write?.length ||
    ts?.agent_cpu?.length ||
    ts?.agent_mem?.length,
  )

  return hasLatest || hasSeries
})

const loadMetrics = async () => {
  if (!props.hostId) return
  loading.value = true
  try {
    metrics.value = await hostsApi.getMetrics(props.hostId, { range: rangeParam.value })
    errorMessage.value = ''
  } catch (error) {
    metrics.value = null
    errorMessage.value =
      (error as any)?.response?.data?.message ||
      (error as Error)?.message ||
      '加载监控数据失败'
    console.error('加载监控数据失败:', error)
  } finally {
    loading.value = false
  }
}

const onRangeChange = () => {
  resetRefresh()
  loadMetrics()
}

const resetRefresh = () => {
  if (refreshTimer) clearInterval(refreshTimer)
  refreshTimer = setInterval(loadMetrics, 60_000)
}

// ---- 工具函数 ----

const getUsageColor = (usage?: number): string => {
  if (!usage) return '#165DFF'
  if (usage >= 90) return '#F53F3F'
  if (usage >= 70) return '#FF7D00'
  return '#00B42A'
}

const getAgentCpuColor = (usage?: number): string => {
  if (!usage) return '#165DFF'
  if (usage >= 50) return '#F53F3F'
  if (usage >= 20) return '#FF7D00'
  return '#00B42A'
}

const formatBytes = (bytes: number): string => {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`
}

const formatTime = (timeStr: string): string => {
  if (!timeStr) return '-'
  let date = new Date(timeStr)
  if (isNaN(date.getTime()) && timeStr.includes(' ')) {
    date = new Date(timeStr.replace(' ', 'T'))
  }
  if (isNaN(date.getTime())) return timeStr
  return date.toLocaleString('zh-CN')
}

const tsToXY = (pts: TimeSeriesPoint[] | undefined) => {
  if (!pts?.length) return { x: [] as string[], y: [] as number[] }
  const x = pts.map(p => {
    const d = new Date(p.timestamp)
    return isNaN(d.getTime()) ? p.timestamp : d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
  })
  const y = pts.map(p => Math.round(p.value * 100) / 100)
  return { x, y }
}

const makeLineOption = (
  xData: string[],
  series: { name: string; data: number[]; color: string }[],
  yUnit = '%',
  yMax?: number,
) => ({
  tooltip: {
    trigger: 'axis',
    formatter: (params: any[]) => params.map((p: any) => {
      let val: string
      if (yUnit === '%') {
        val = `${p.value}%`
      } else {
        const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB']
        const v = p.value || 0
        const i = v === 0 ? 0 : Math.min(Math.floor(Math.log(Math.abs(v)) / Math.log(k)), sizes.length - 1)
        val = `${(v / Math.pow(k, i)).toFixed(1)} ${sizes[i]}/s`
      }
      return `${p.marker}${p.seriesName}: ${val}`
    }).join('<br/>'),
  },
  legend: { show: series.length > 1, bottom: 4, textStyle: { fontSize: 12 } },
  grid: { top: 8, right: 12, bottom: series.length > 1 ? 48 : 24, left: 12, containLabel: true },
  xAxis: {
    type: 'category',
    data: xData,
    axisLabel: { fontSize: 11, color: '#86909C' },
    axisLine: { lineStyle: { color: '#E5E6EB' } },
    axisTick: { show: false },
  },
  yAxis: {
    type: 'value',
    max: yMax,
    axisLabel: { fontSize: 11, color: '#86909C', formatter: (v: number) => {
      if (yUnit === '%') return `${v}%`
      const k = 1024
      const sizes = ['B', 'KB', 'MB', 'GB']
      if (v === 0) return `0 B`
      const i = Math.min(Math.floor(Math.log(Math.abs(v)) / Math.log(k)), sizes.length - 1)
      return `${(v / Math.pow(k, i)).toFixed(0)} ${sizes[i]}`
    } },
    splitLine: { lineStyle: { color: '#F2F3F5' } },
  },
  series: series.map(s => ({
    name: s.name,
    type: 'line',
    data: s.data,
    smooth: true,
    symbol: 'none',
    lineStyle: { color: s.color, width: 2 },
    areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: s.color + '33' }, { offset: 1, color: s.color + '00' }] } },
  })),
})

// ---- ECharts option 计算 ----

const cpuOption = computed(() => {
  const ts = metrics.value?.time_series
  if (!ts?.cpu_usage?.length) return null
  const { x, y } = tsToXY(ts.cpu_usage)
  return makeLineOption(x, [{ name: 'CPU', data: y, color: '#165DFF' }], '%', 100)
})

const memOption = computed(() => {
  const ts = metrics.value?.time_series
  if (!ts?.mem_usage?.length) return null
  const { x, y } = tsToXY(ts.mem_usage)
  return makeLineOption(x, [{ name: '内存', data: y, color: '#722ED1' }], '%', 100)
})

const netOption = computed(() => {
  const ts = metrics.value?.time_series
  if (!ts?.net_in?.length && !ts?.net_out?.length) return null
  const { x: xi, y: yi } = tsToXY(ts.net_in)
  const { x: xo, y: yo } = tsToXY(ts.net_out)
  const x = xi.length >= xo.length ? xi : xo
  return makeLineOption(x, [
    { name: '接收', data: yi, color: '#14C9C9' },
    { name: '发送', data: yo, color: '#00B42A' },
  ], ' KB/s')
})

const diskIOOption = computed(() => {
  const ts = metrics.value?.time_series
  if (!ts?.disk_read?.length && !ts?.disk_write?.length) return null
  const { x: xr, y: yr } = tsToXY(ts.disk_read)
  const { x: xw, y: yw } = tsToXY(ts.disk_write)
  const x = xr.length >= xw.length ? xr : xw
  return makeLineOption(x, [
    { name: '读取', data: yr, color: '#FF7D00' },
    { name: '写入', data: yw, color: '#F53F3F' },
  ], ' KB/s')
})

const agentCpuOption = computed(() => {
  const ts = metrics.value?.time_series
  if (!ts?.agent_cpu?.length) return null
  const { x, y } = tsToXY(ts.agent_cpu)
  return makeLineOption(x, [{ name: 'Agent CPU', data: y, color: '#EB2F96' }], '%')
})

const agentMemOption = computed(() => {
  const ts = metrics.value?.time_series
  if (!ts?.agent_mem?.length) return null
  const { x, y: raw } = tsToXY(ts.agent_mem)
  // bytes -> MB
  const y = raw.map(v => Math.round(v / 1024 / 1024 * 10) / 10)
  return makeLineOption(x, [{ name: 'Agent 内存', data: y, color: '#13C2C2' }], ' MB')
})

onMounted(() => {
  loadMetrics()
  resetRefresh()
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped lang="less">
.performance-monitor {
  width: 100%;
}

.top-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.source-info {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 13px;
  color: #595959;
}

.source-tag {
  background: #E8F3FF;
  color: #165DFF;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.source-time {
  color: #86909C;
  display: flex;
  align-items: center;
}

.state-alert {
  margin-bottom: 16px;
}

.metrics-row {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.metric-card {
  flex: 1;
  min-width: 160px;
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 16px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03), 0 2px 4px rgba(0,0,0,0.04);
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
  }
}

.metric-icon-bg {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  flex-shrink: 0;
  color: #fff;
}

.cpu-bg  { background: linear-gradient(135deg, #165DFF, #0E42D2); }
.mem-bg  { background: linear-gradient(135deg, #722ED1, #531DAB); }
.disk-bg { background: linear-gradient(135deg, #D25F00, #d46b08); }
.net-send-bg { background: linear-gradient(135deg, #00B42A, #009A29); }
.io-bg   { background: linear-gradient(135deg, #FF7D00, #E06400); }
.agent-cpu-bg { background: linear-gradient(135deg, #EB2F96, #C41D7F); }
.agent-mem-bg { background: linear-gradient(135deg, #13C2C2, #08979C); }

.metric-info { flex: 1; min-width: 0; }

.metric-label {
  font-size: 12px;
  color: #86909C;
  margin-bottom: 4px;
  white-space: nowrap;
}

.metric-value {
  font-size: 24px;
  font-weight: 700;
  line-height: 1;
  margin-bottom: 8px;

  &.net {
    font-size: 14px;
    color: #262626;
    font-weight: 600;
    margin-bottom: 0;
    white-space: nowrap;
  }
}

.metric-unit {
  font-size: 13px;
  font-weight: 400;
  margin-left: 2px;
}

.metric-sep {
  color: #C9CDD4;
  margin: 0 4px;
}

/* 图表网格 */
.charts-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.chart-card {
  background: #fff;
  border-radius: 8px;
  padding: 16px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03), 0 2px 4px rgba(0,0,0,0.04);
}

.chart-title {
  font-size: 14px;
  font-weight: 600;
  color: #262626;
  margin-bottom: 12px;
}

.chart {
  height: 180px;
  width: 100%;
}
</style>
