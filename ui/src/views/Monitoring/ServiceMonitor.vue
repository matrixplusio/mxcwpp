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
                <div class="metric-value">{{ svc.qps }}</div>
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
          <div class="service-meta">
            <span>PID: {{ svc.pid }}</span>
            <span>运行时间: {{ svc.uptime }}</span>
            <span>版本: {{ svc.version }}</span>
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

interface ServiceInfo {
  name: string
  status: string
  qps: number
  cpu: number
  memory: string
  pid: string
  uptime: string
  version: string
  detail?: string
}

type QPSPoint = Record<string, string | number>

const timeRange = ref('1h')
const qpsPalette = ['#165DFF', '#00B42A', '#FF7D00', '#F53F3F', '#722ED1', '#14C9C9']

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
    borderColor: '#E5E8EF',
    textStyle: { color: '#1D2129', fontSize: 12 },
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
    borderColor: '#E5E8EF',
    textStyle: { color: '#1D2129', fontSize: 12 },
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
    { name: 'P50', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#165DFF' }, data: latencyData.value.map(d => d.p50 ?? 0) },
    { name: 'P95', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#FF7D00' }, data: latencyData.value.map(d => d.p95 ?? 0) },
    { name: 'P99', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#F53F3F' }, data: latencyData.value.map(d => d.p99 ?? 0) },
  ],
}))

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
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
  transition: border-color 0.2s;
}
.service-card:hover { border-color: #165DFF; }
.service-card.service-error { border-color: #FDCDC5; }

.service-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.service-info { display: flex; align-items: center; gap: 10px; }
.service-name { font-size: 16px; font-weight: 600; color: #1D2129; }

.status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.dot-healthy { background: #00B42A; box-shadow: 0 0 0 3px rgba(0,180,42,0.15); }
.dot-warning { background: #FF7D00; box-shadow: 0 0 0 3px rgba(255,125,0,0.15); }
.dot-error { background: #F53F3F; box-shadow: 0 0 0 3px rgba(245,63,63,0.15); }

.service-metrics { margin-bottom: 16px; }
.metric-item { text-align: center; }
.metric-value { font-size: 20px; font-weight: 600; color: #1D2129; }
.metric-label { font-size: 12px; color: #86909C; margin-top: 2px; }

.service-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  font-size: 12px;
  color: #86909C;
  padding-top: 12px;
  border-top: 1px solid #F2F3F5;
}

.service-detail {
  margin-top: 10px;
  font-size: 12px;
  color: #4E5969;
  word-break: break-all;
}

.dashboard-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  height: 100%;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid #F2F3F5;
}
.card-title { font-size: 14px; font-weight: 600; color: #1D2129; }
.card-body { padding: 16px 20px; }
.chart-container { display: flex; align-items: center; justify-content: center; }
</style>
