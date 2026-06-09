<template>
  <div class="host-monitor-page">
    <div class="page-header">
      <h2>主机监控</h2>
      <span class="page-header-hint">实时监控服务器资源使用情况</span>
    </div>

    <!-- 概览统计 (统一 StatCard) -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="4" v-for="item in overviewStats" :key="item.key">
        <StatCard
          :title="item.label"
          :value="item.value"
          :color="item.statusColor === 'red' ? '#EF4444' : item.statusColor === 'orange' ? '#F59E0B' : '#22C55E'"
          :tags="[{ label: item.statusText, color: item.statusColor === 'red' ? '#EF4444' : item.statusColor === 'orange' ? '#F59E0B' : '#22C55E' }, { label: `${item.trend > 0 ? '+' : ''}${item.trend}% vs 昨日`, color: item.trend > 0 ? '#EF4444' : '#22C55E' }]"
        />
      </a-col>
    </a-row>

    <!-- CPU / Memory 趋势图 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">CPU 使用率趋势</span>
            <a-radio-group v-model:value="timeRange" size="small" @change="loadMetrics">
              <a-radio-button value="1h">1 小时</a-radio-button>
              <a-radio-button value="6h">6 小时</a-radio-button>
              <a-radio-button value="24h">24 小时</a-radio-button>
            </a-radio-group>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="cpuData.length > 0" :option="cpuChartOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无数据" />
          </div>
        </div>
      </a-col>
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">内存使用率趋势</span>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="memoryData.length > 0" :option="memoryChartOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无数据" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 磁盘 / 网络 趋势图 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">磁盘 I/O</span>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="diskData.length > 0" :option="diskChartOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无数据" />
          </div>
        </div>
      </a-col>
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">网络流量</span>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="networkData.length > 0" :option="networkChartOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无数据" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 磁盘分区使用情况 -->
    <div class="dashboard-card section-row">
      <div class="card-header">
        <span class="card-title">磁盘分区使用情况</span>
      </div>
      <div class="card-body">
        <a-table :columns="diskColumns" :data-source="diskPartitions" :pagination="false" size="middle">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'usage'">
              <a-progress
                :percent="parseFloat(record.usagePercent.toFixed(1))"
                :stroke-color="record.usagePercent > 90 ? '#EF4444' : record.usagePercent > 70 ? '#F59E0B' : '#3B82F6'"
                :size="6"
              />
            </template>
            <template v-if="column.key === 'status'">
              <a-tag :color="record.usagePercent > 90 ? 'red' : record.usagePercent > 70 ? 'orange' : 'green'" :bordered="false">
                {{ record.usagePercent > 90 ? '告警' : record.usagePercent > 70 ? '注意' : '正常' }}
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
import StatCard from '@/components/StatCard.vue'
import apiClient from '@/api/client'

const timeRange = ref('1h')

// 概览统计
const overviewStats = ref([
  { key: 'cpu', label: 'CPU 使用率', value: '0%', statusColor: 'green', statusText: '正常', trend: 0 },
  { key: 'memory', label: '内存使用率', value: '0%', statusColor: 'green', statusText: '正常', trend: 0 },
  { key: 'disk', label: '磁盘使用率', value: '0%', statusColor: 'green', statusText: '正常', trend: 0 },
  { key: 'load', label: '系统负载', value: '0.00', statusColor: 'green', statusText: '正常', trend: 0 },
  { key: 'agentCpu', label: 'Agent CPU', value: '0%', statusColor: 'green', statusText: '正常', trend: 0 },
  { key: 'agentMem', label: 'Agent 内存', value: '0 MB', statusColor: 'green', statusText: '正常', trend: 0 },
])

// 图表数据
const cpuData = ref<any[]>([])
const memoryData = ref<any[]>([])
const diskData = ref<any[]>([])
const networkData = ref<any[]>([])

// 磁盘分区
const diskPartitions = ref<any[]>([])
const diskColumns = [
  { title: '挂载点', dataIndex: 'mountPoint', key: 'mountPoint' },
  { title: '文件系统', dataIndex: 'filesystem', key: 'filesystem' },
  { title: '总容量', dataIndex: 'total', key: 'total' },
  { title: '已使用', dataIndex: 'used', key: 'used' },
  { title: '可用', dataIndex: 'available', key: 'available' },
  { title: '使用率', key: 'usage', width: 200 },
  { title: '状态', key: 'status', width: 100 },
]

const makeLineOption = (_title: string, data: any[], seriesConfig: any[]) => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: '#fff',
    borderColor: 'rgba(30, 58, 95, 0.4)',
    textStyle: { color: '#E5E5E5', fontSize: 12 },
  },
  legend: {
    bottom: 0,
    itemWidth: 12, itemHeight: 3,
    textStyle: { color: '#86909C', fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 56 },
  xAxis: {
    type: 'category',
    data: data.map(d => d.time),
    axisLine: { lineStyle: { color: '#E5E6EB' } },
    axisLabel: { color: '#86909C', fontSize: 11 },
    axisTick: { show: false },
  },
  yAxis: {
    type: 'value',
    axisLine: { show: false },
    axisLabel: { color: '#86909C', fontSize: 11, formatter: '{value}%' },
    splitLine: { lineStyle: { color: '#F2F3F5' } },
    max: 100,
  },
  series: seriesConfig.map(s => ({
    name: s.name,
    type: 'line',
    smooth: true,
    symbol: 'none',
    lineStyle: { width: 2 },
    areaStyle: { opacity: 0.05 },
    itemStyle: { color: s.color },
    data: data.map(d => d[s.field] ?? 0),
  })),
})

const cpuChartOption = computed(() =>
  makeLineOption('CPU', cpuData.value, [
    { name: 'CPU 使用率', field: 'usage', color: '#3B82F6' },
  ])
)

const memoryChartOption = computed(() =>
  makeLineOption('Memory', memoryData.value, [
    { name: '内存使用率', field: 'usage', color: '#22C55E' },
  ])
)

const diskChartOption = computed(() => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: '#fff',
    borderColor: 'rgba(30, 58, 95, 0.4)',
    textStyle: { color: '#E5E5E5', fontSize: 12 },
  },
  legend: {
    bottom: 0,
    itemWidth: 12, itemHeight: 3,
    textStyle: { color: '#86909C', fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 56 },
  xAxis: {
    type: 'category',
    data: diskData.value.map(d => d.time),
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
    { name: '读取 (KB/s)', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#3B82F6' }, data: diskData.value.map(d => d.read ?? 0) },
    { name: '写入 (KB/s)', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#F59E0B' }, data: diskData.value.map(d => d.write ?? 0) },
  ],
}))

const networkChartOption = computed(() => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: '#fff',
    borderColor: 'rgba(30, 58, 95, 0.4)',
    textStyle: { color: '#E5E5E5', fontSize: 12 },
  },
  legend: {
    bottom: 0,
    itemWidth: 12, itemHeight: 3,
    textStyle: { color: '#86909C', fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 56 },
  xAxis: {
    type: 'category',
    data: networkData.value.map(d => d.time),
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
    { name: '入站 (KB/s)', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, areaStyle: { opacity: 0.05 }, itemStyle: { color: '#3B82F6' }, data: networkData.value.map(d => d.inbound ?? 0) },
    { name: '出站 (KB/s)', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, areaStyle: { opacity: 0.05 }, itemStyle: { color: '#22C55E' }, data: networkData.value.map(d => d.outbound ?? 0) },
  ],
}))

const loadMetrics = async () => {
  try {
    const res = await apiClient.get<any>('/monitor/host', { params: { range: timeRange.value } })
    if (res.overview) {
      const agentCpu = res.overview.agentCpu ?? 0
      const agentMem = res.overview.agentMemMB ?? 0
      overviewStats.value = [
        { key: 'cpu', label: 'CPU 使用率', value: `${(res.overview.cpu ?? 0).toFixed(1)}%`, statusColor: res.overview.cpu > 90 ? 'red' : res.overview.cpu > 70 ? 'orange' : 'green', statusText: res.overview.cpu > 90 ? '告警' : res.overview.cpu > 70 ? '注意' : '正常', trend: res.overview.cpuTrend ?? 0 },
        { key: 'memory', label: '内存使用率', value: `${(res.overview.memory ?? 0).toFixed(1)}%`, statusColor: res.overview.memory > 90 ? 'red' : res.overview.memory > 70 ? 'orange' : 'green', statusText: res.overview.memory > 90 ? '告警' : res.overview.memory > 70 ? '注意' : '正常', trend: res.overview.memoryTrend ?? 0 },
        { key: 'disk', label: '磁盘使用率', value: `${(res.overview.disk ?? 0).toFixed(1)}%`, statusColor: res.overview.disk > 90 ? 'red' : res.overview.disk > 70 ? 'orange' : 'green', statusText: res.overview.disk > 90 ? '告警' : res.overview.disk > 70 ? '注意' : '正常', trend: res.overview.diskTrend ?? 0 },
        { key: 'load', label: '系统负载', value: `${res.overview.load ?? '0.00'}`, statusColor: 'green', statusText: '正常', trend: res.overview.loadTrend ?? 0 },
        { key: 'agentCpu', label: 'Agent CPU', value: `${agentCpu.toFixed(1)}%`, statusColor: agentCpu > 50 ? 'red' : agentCpu > 20 ? 'orange' : 'green', statusText: agentCpu > 50 ? '偏高' : agentCpu > 20 ? '注意' : '正常', trend: 0 },
        { key: 'agentMem', label: 'Agent 内存', value: `${(res.overview.agentMemPercent ?? 0).toFixed(1)}% (${agentMem.toFixed(1)} MB)`, statusColor: agentMem > 512 ? 'red' : agentMem > 256 ? 'orange' : 'green', statusText: agentMem > 512 ? '偏高' : agentMem > 256 ? '注意' : '正常', trend: 0 },
      ]
    }
    cpuData.value = res.cpu ?? []
    memoryData.value = res.memory ?? []
    diskData.value = res.disk ?? []
    networkData.value = res.network ?? []
    diskPartitions.value = res.partitions ?? []
  } catch {
    // API 未就绪, 保持空数据
  }
}

let timer: number | null = null
onMounted(() => {
  loadMetrics()
  timer = window.setInterval(loadMetrics, 30000)
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.host-monitor-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.monitor-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
}
.stat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}
.stat-label { font-size: 13px; color: var(--mxsec-text-3); }
.stat-value { font-size: 28px; font-weight: 700; color: var(--mxsec-text-1); line-height: 1.2; }
.stat-trend { margin-top: 8px; font-size: 12px; }
.trend-label { color: var(--mxsec-text-3); margin-right: 4px; }
.trend-up { color: #EF4444; }
.trend-down { color: #22C55E; }

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
.chart-container {
  display: flex;
  align-items: center;
  justify-content: center;
}
</style>
