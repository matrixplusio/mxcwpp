<template>
  <div class="service-monitor-page">
    <div class="page-header">
      <h2>后端服务</h2>
      <span class="page-header-hint">监控各后端服务运行状态与性能指标</span>
    </div>

    <!-- 服务概览卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col v-for="svc in services" :key="svc.name" :xs="24" :md="12" :xl="8">
        <div class="service-card" :class="{ 'service-error': svc.status === 'error' }">
          <div class="service-card-header">
            <div class="service-info">
              <span class="status-dot" :class="`dot-${svc.status}`"></span>
              <span class="service-name">{{ svc.name }}</span>
            </div>
            <a-tag :color="statusColorMap[svc.status]" :bordered="false">
              {{ statusTextMap[svc.status] }}
            </a-tag>
          </div>
          <a-row :gutter="16" class="service-metrics">
            <a-col :span="8">
              <div class="metric-item">
                <div class="metric-value">{{ formatQps(svc.qps) }}</div>
                <div class="metric-label">QPS</div>
              </div>
            </a-col>
            <a-col :span="8">
              <div class="metric-item">
                <div class="metric-value">{{ svc.cpu }}%</div>
                <div class="metric-label">CPU</div>
              </div>
            </a-col>
            <a-col :span="8">
              <div class="metric-item">
                <div class="metric-value">{{ svc.memory }}</div>
                <div class="metric-label">内存</div>
              </div>
            </a-col>
          </a-row>
          <!-- v2 强类型指标（来自 PromQL 真实数据） -->
          <a-row v-if="hasV2Metrics(svc)" :gutter="16" class="service-metrics-v2">
            <a-col v-if="svc.p99LatencyMs !== undefined && svc.p99LatencyMs > 0" :span="8">
              <div class="metric-item-v2">
                <span class="metric-v2-label">p99</span>
                <span class="metric-v2-value">{{ svc.p99LatencyMs.toFixed(1) }}ms</span>
              </div>
            </a-col>
            <a-col v-if="svc.errorRate !== undefined && svc.errorRate > 0" :span="8">
              <div class="metric-item-v2" :class="{ 'error-warn': svc.errorRate > 0.05 }">
                <span class="metric-v2-label">错误率</span>
                <span class="metric-v2-value">{{ (svc.errorRate * 100).toFixed(2) }}%</span>
              </div>
            </a-col>
            <a-col v-if="svc.connections !== undefined && svc.connections > 0" :span="8">
              <div class="metric-item-v2">
                <span class="metric-v2-label">连接数</span>
                <span class="metric-v2-value">{{ svc.connections }}</span>
              </div>
            </a-col>
            <a-col v-if="svc.queueLag !== undefined && svc.queueLag > 0" :span="8">
              <div class="metric-item-v2" :class="{ 'error-warn': svc.queueLag > 10000 }">
                <span class="metric-v2-label">队列积压</span>
                <span class="metric-v2-value">{{ svc.queueLag }}</span>
              </div>
            </a-col>
            <a-col v-if="svc.goroutineCount !== undefined && svc.goroutineCount > 0" :span="8">
              <div class="metric-item-v2" :class="{ 'error-warn': svc.goroutineCount > 10000 }">
                <span class="metric-v2-label">goroutine</span>
                <span class="metric-v2-value">{{ svc.goroutineCount }}</span>
              </div>
            </a-col>
            <a-col v-if="svc.gcPauseP99Ms !== undefined && svc.gcPauseP99Ms > 0" :span="8">
              <div class="metric-item-v2" :class="{ 'error-warn': svc.gcPauseP99Ms > 500 }">
                <span class="metric-v2-label">GC p99</span>
                <span class="metric-v2-value">{{ svc.gcPauseP99Ms }}ms</span>
              </div>
            </a-col>
          </a-row>
          <div class="service-meta">
            <span>PID: {{ svc.pid }}</span>
            <span>运行: {{ svc.uptime }}</span>
            <span>版本: {{ svc.version }}</span>
            <span v-if="svc.dataSource" class="data-source-badge" :title="`数据来源: ${svc.dataSource}`">
              {{ dataSourceLabel(svc.dataSource) }}
            </span>
          </div>
          <div v-if="svc.detail" class="service-detail">{{ svc.detail }}</div>
        </div>
      </a-col>
    </a-row>

    <!-- QPS 趋势 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">请求 QPS 趋势</span>
            <a-radio-group v-model:value="timeRange" size="small" @change="loadData">
              <a-radio-button value="1h">1 小时</a-radio-button>
              <a-radio-button value="6h">6 小时</a-radio-button>
              <a-radio-button value="24h">24 小时</a-radio-button>
            </a-radio-group>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="hasQpsSeries" :option="qpsChartOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无数据" />
          </div>
        </div>
      </a-col>
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">响应时间分布</span>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="latencyData.length > 0" :option="latencyChartOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无数据" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- gRPC / API 连接统计 -->
    <div class="dashboard-card section-row">
      <div class="card-header">
        <span class="card-title">连接统计</span>
      </div>
      <div class="card-body">
        <a-table :columns="connColumns" :data-source="connectionStats" :pagination="false" size="middle">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="connectionStatusColor(record.status)" :bordered="false">
                {{ connectionStatusText(record.status) }}
              </a-tag>
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import apiClient from '@/api/client'

// v2 schema：前向兼容旧字段，新增强类型字段
// 后端来自 internal/server/manager/api/monitor.go:serviceInfo
interface ServiceInfo {
  name: string
  status: string
  qps: number          // float64（真实 QPS，rate per second）
  cpu: number          // 0-100 percent
  memory: string       // 人类可读"234 MB"
  pid: string
  uptime: string
  version: string
  detail?: string
  // v2 字段（optional，prometheus 数据缺失时 undefined）
  memRssBytes?: number
  p99LatencyMs?: number
  errorRate?: number        // [0, 1]
  connections?: number
  queueLag?: number
  uptimeSec?: number
  extra?: Record<string, string>
  dataSource?: string       // prometheus / driver / driver+prometheus / sd-registry
  goroutineCount?: number
  fdCount?: number
  gcPauseP99Ms?: number
}

type QPSPoint = Record<string, string | number>

const timeRange = ref('1h')
const qpsPalette = ['#3B82F6', '#22C55E', '#F59E0B', '#EF4444', '#722ED1', '#14C9C9']

const statusColorMap: Record<string, string> = {
  healthy: 'green', warning: 'orange', error: 'red',
}
const statusTextMap: Record<string, string> = {
  healthy: '正常', warning: '警告', error: '异常',
}

const services = ref<ServiceInfo[]>([])
const qpsData = ref<QPSPoint[]>([])
const latencyData = ref<any[]>([])
const connectionStats = ref<any[]>([])

const connColumns = [
  { title: '服务', dataIndex: 'service', key: 'service' },
  { title: '协议', dataIndex: 'protocol', key: 'protocol' },
  { title: '监听地址', dataIndex: 'address', key: 'address' },
  { title: '活跃连接', dataIndex: 'activeConnections', key: 'activeConnections' },
  { title: '总连接数', dataIndex: 'totalConnections', key: 'totalConnections' },
  { title: '状态', key: 'status', width: 100 },
]

const qpsSeriesKeys = computed(() => {
  const keys = new Set<string>()
  qpsData.value.forEach(point => {
    Object.keys(point).forEach(key => {
      if (key !== 'time') keys.add(key)
    })
  })
  return Array.from(keys)
})

const hasQpsSeries = computed(() => qpsData.value.length > 0 && qpsSeriesKeys.value.length > 0)

const qpsChartOption = computed(() => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: '#fff',
    borderColor: 'rgba(30, 58, 95, 0.4)',
    textStyle: { color: '#E5E5E5', fontSize: 12 },
  },
  legend: {
    bottom: 0, itemWidth: 12, itemHeight: 3,
    textStyle: { color: '#86909C', fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 56 },
  xAxis: {
    type: 'category',
    data: qpsData.value.map(d => d.time),
    axisLine: { lineStyle: { color: '#E5E6EB' } },
    axisLabel: { color: '#86909C', fontSize: 11 },
    axisTick: { show: false },
  },
  yAxis: {
    type: 'value',
    axisLine: { show: false },
    axisLabel: { color: '#86909C', fontSize: 11 },
    splitLine: { lineStyle: { color: '#F2F3F5' } },
  },
  series: [
    ...qpsSeriesKeys.value.map((key, index) => ({
      name: key,
      type: 'line',
      smooth: true,
      symbol: 'none',
      lineStyle: { width: 2 },
      itemStyle: { color: qpsPalette[index % qpsPalette.length] },
      data: qpsData.value.map(d => Number(d[key] ?? 0)),
    })),
  ],
}))

const latencyChartOption = computed(() => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: '#fff',
    borderColor: 'rgba(30, 58, 95, 0.4)',
    textStyle: { color: '#E5E5E5', fontSize: 12 },
  },
  legend: {
    bottom: 0, itemWidth: 12, itemHeight: 3,
    textStyle: { color: '#86909C', fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 56 },
  xAxis: {
    type: 'category',
    data: latencyData.value.map(d => d.time),
    axisLine: { lineStyle: { color: '#E5E6EB' } },
    axisLabel: { color: '#86909C', fontSize: 11 },
    axisTick: { show: false },
  },
  yAxis: {
    type: 'value',
    axisLine: { show: false },
    axisLabel: { color: '#86909C', fontSize: 11, formatter: '{value} ms' },
    splitLine: { lineStyle: { color: '#F2F3F5' } },
  },
  series: [
    { name: 'P50', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#3B82F6' }, data: latencyData.value.map(d => d.p50 ?? 0) },
    { name: 'P95', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#F59E0B' }, data: latencyData.value.map(d => d.p95 ?? 0) },
    { name: 'P99', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#EF4444' }, data: latencyData.value.map(d => d.p99 ?? 0) },
  ],
}))

// QPS 格式化：> 1 显示整数，< 1 显示 2 位小数
const formatQps = (qps: number): string => {
  if (qps === undefined || qps === null) return '--'
  if (qps === 0) return '0'
  if (qps >= 1) return Math.round(qps).toString()
  return qps.toFixed(2)
}

// 判断是否有任一 v2 指标可显示
const hasV2Metrics = (svc: ServiceInfo): boolean => {
  return !!(
    (svc.p99LatencyMs && svc.p99LatencyMs > 0) ||
    (svc.errorRate && svc.errorRate > 0) ||
    (svc.connections && svc.connections > 0) ||
    (svc.queueLag && svc.queueLag > 0) ||
    (svc.goroutineCount && svc.goroutineCount > 0) ||
    (svc.gcPauseP99Ms && svc.gcPauseP99Ms > 0)
  )
}

const dataSourceLabel = (src: string): string => {
  switch (src) {
    case 'prometheus': return 'Prom'
    case 'driver': return 'Driver'
    case 'driver+prometheus': return 'Driver+Prom'
    case 'prometheus+driver': return 'Prom+Driver'
    default: return src
  }
}

const connectionStatusColor = (status: string) => {
  if (status === 'warning') return 'orange'
  if (status === 'error') return 'red'
  return 'green'
}

const connectionStatusText = (status: string) => {
  if (status === 'warning') return '告警'
  if (status === 'error') return '异常'
  return '活跃'
}

const loadData = async () => {
  try {
    const res = await apiClient.get<any>('/monitor/services', { params: { range: timeRange.value } })
    services.value = Array.isArray(res.services) ? res.services : []
    qpsData.value = Array.isArray(res.qps) ? res.qps : []
    latencyData.value = Array.isArray(res.latency) ? res.latency : []
    connectionStats.value = Array.isArray(res.connections) ? res.connections : []
  } catch {
    // API 未就绪
  }
}

let timer: number | null = null
onMounted(() => {
  loadData()
  timer = window.setInterval(loadData, 30000)
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.service-monitor-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.service-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  transition: border-color 0.2s;
  /* 等高：同行卡片高度由最高者撑齐，避免 MySQL/CH 长字符串撑高单卡 */
  height: 100%;
  display: flex;
  flex-direction: column;
}
.service-card:hover { border-color: var(--mxsec-primary); }
.service-card.service-error { border-color: #FDCDC5; }
.service-card .service-detail { margin-top: auto; }
/* 主指标值 nowrap，超长省略号，防止单值换行撑高卡 */
.metric-value { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.service-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.service-info { display: flex; align-items: center; gap: 10px; }
.service-name { font-size: 16px; font-weight: 600; color: var(--mxsec-text-1); }

.status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot-healthy { background: #22C55E; box-shadow: 0 0 0 3px rgba(0,180,42,0.15); }
.dot-warning { background: #F59E0B; box-shadow: 0 0 0 3px rgba(255,125,0,0.15); }
.dot-error { background: #EF4444; box-shadow: 0 0 0 3px rgba(245,63,63,0.15); }

.service-metrics { margin-bottom: 16px; }
.metric-item { text-align: center; }
.metric-value { font-size: 20px; font-weight: 600; color: var(--mxsec-text-1); }
.metric-label { font-size: 12px; color: var(--mxsec-text-3); margin-top: 2px; }

/* v2 强类型指标（p99/error_rate/connections/queueLag/goroutine/gc_pause） */
.service-metrics-v2 {
  margin-bottom: 12px;
  padding-top: 12px;
  border-top: 1px dashed var(--mxsec-fill-2);
}
.metric-item-v2 {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  padding: 4px 8px;
  margin-bottom: 4px;
  border-radius: 4px;
  background: var(--mxsec-fill-1);
  font-size: 12px;
}
.metric-item-v2.error-warn { background: rgba(239, 68, 68, 0.08); }
.metric-v2-label { color: var(--mxsec-text-3); }
.metric-v2-value { font-weight: 600; color: var(--mxsec-text-1); }
.metric-item-v2.error-warn .metric-v2-value { color: #EF4444; }

.service-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 12px;
  color: var(--mxsec-text-3);
  padding-top: 12px;
  border-top: 1px solid var(--mxsec-fill-2);
}

.data-source-badge {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  background: var(--mxsec-fill-2);
  color: var(--mxsec-text-3);
  cursor: help;
}

.service-detail {
  margin-top: 10px;
  font-size: 12px;
  color: var(--mxsec-text-2);
  word-break: break-all;
}

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  height: 100%;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--mxsec-border-light);
}
.card-title { font-size: 14px; font-weight: 600; color: var(--mxsec-text-1); }
.card-body { padding: 16px 20px; }
.chart-container { display: flex; align-items: center; justify-content: center; }
</style>
