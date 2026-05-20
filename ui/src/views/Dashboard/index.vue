<template>
  <div class="dashboard-page">
    <!-- 页面标题 -->
    <div class="page-header">
      <h2>安全概览</h2>
      <span class="page-header-hint">实时监控平台安全态势</span>
    </div>

    <!-- 第一行: 资产统计卡片 (参考 Elkeid DescribeAgent / DescribeAsset) -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="4" v-for="item in assetStats" :key="item.key">
        <div class="stat-card-item" @click="item.route && $router.push(item.route)">
          <div class="stat-card-icon" :style="{ background: item.gradient }">
            <component :is="item.icon" />
          </div>
          <div class="stat-card-value">{{ item.value }}</div>
          <div class="stat-card-label">{{ item.label }}</div>
          <div v-if="item.change !== undefined && item.change !== 0" class="stat-card-change" :class="item.change > 0 ? 'change-up' : 'change-down'">
            <ArrowUpOutlined v-if="item.change > 0" />
            <ArrowDownOutlined v-else />
            {{ Math.abs(item.change) }} 较昨日
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 第二行: 告警趋势 (左) + 安全风险分布 (右) -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="14">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">威胁告警趋势</span>
            <a-radio-group v-model:value="alertTrendRange" size="small">
              <a-radio-button value="7d">近 7 天</a-radio-button>
              <a-radio-button value="30d">近 30 天</a-radio-button>
            </a-radio-group>
          </div>
          <div class="card-body chart-container">
            <v-chart v-if="filteredTrendData.length > 0" :option="alertTrendOption" autoresize style="height: 280px" />
            <a-empty v-else description="暂无告警数据" />
          </div>
        </div>
      </a-col>
      <a-col :span="10">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">安全风险分布</span>
          </div>
          <div class="card-body chart-container">
            <v-chart :option="riskRadarOption" autoresize style="height: 280px" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 第三行: Agent 状态饼图 (左) + 基线安全统计 (中) + 服务健康 (右) -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="8">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">Agent 状态分布</span>
          </div>
          <div class="card-body chart-container">
            <v-chart :option="agentPieOption" autoresize style="height: 240px" />
          </div>
        </div>
      </a-col>
      <a-col :span="8">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">基线安全统计</span>
          </div>
          <div class="card-body">
            <div class="compliance-ring">
              <a-progress
                type="circle"
                :percent="stats.baselineHardeningPercent || 0"
                :size="120"
                :stroke-color="getPassRateColor(stats.baselineHardeningPercent)"
                :format="(p: number) => `${p}%`"
              />
              <div class="compliance-label">整体合规率</div>
            </div>
            <div class="compliance-detail">
              <div class="detail-row">
                <span class="detail-label">检查主机数</span>
                <span class="detail-value">{{ stats.hosts || 0 }}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">不合规率(中危+)</span>
                <span class="detail-value text-danger">{{ stats.baselineHostPercent || 0 }}%</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">待修复风险项</span>
                <span class="detail-value text-danger">{{ stats.baselineFailCount || 0 }}</span>
              </div>
            </div>
          </div>
        </div>
      </a-col>
      <a-col :span="8">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">最新告警</span>
            <a class="card-link" @click="$router.push('/alerts')">查看全部</a>
          </div>
          <div class="card-body latest-alerts-body">
            <div v-if="latestAlerts.length > 0" class="alert-list">
              <div
                v-for="alert in latestAlerts"
                :key="alert.id"
                class="alert-item"
                @click="$router.push(`/alerts/${alert.id}`)"
              >
                <span class="alert-severity-dot" :style="{ background: severityColor(alert.severity) }"></span>
                <div class="alert-main">
                  <div class="alert-title" :title="alert.title">{{ alert.title }}</div>
                  <div class="alert-meta">
                    <span class="alert-host">{{ alert.hostname || '未知主机' }}</span>
                    <span class="alert-time">{{ formatRelativeTime(alert.last_seen_at) }}</span>
                  </div>
                </div>
              </div>
            </div>
            <a-empty v-else description="暂无告警" style="padding: 40px 0" />
          </div>
        </div>
      </a-col>
    </a-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import {
  DesktopOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  BugOutlined,
  SafetyOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
} from '@ant-design/icons-vue'
import { dashboardApi } from '@/api/dashboard'
import type { DashboardStats, BaselineRisk, AlertTrendItem, LatestAlert } from '@/api/dashboard'

// ========== 数据 ==========
const stats = ref<DashboardStats>({
  hosts: 0, clusters: 0, containers: 0,
  onlineAgents: 0, offlineAgents: 0,
  pendingAlerts: 0, pendingVulnerabilities: 0,
  vulnDbUpdateTime: '', baselineFailCount: 0,
  baselineHardeningPercent: 0,
})

const baselineRisks = ref<BaselineRisk[]>([])
const alertTrendRange = ref<'7d' | '30d'>('7d')
const alertTrendData = ref<AlertTrendItem[]>([])
const latestAlerts = ref<LatestAlert[]>([])

// 告警趋势按时间窗口本地切片（后端统一返回最近 30 天）
const filteredTrendData = computed(() => {
  const days = alertTrendRange.value === '7d' ? 7 : 30
  return alertTrendData.value.slice(-days)
})

// ========== 资产统计卡片 ==========
const assetStats = computed<Array<{
  key: string
  label: string
  value: number
  icon: any
  gradient: string
  route?: string
  change?: number
}>>(() => [
  {
    key: 'hosts', label: '主机总数', value: stats.value.hosts,
    icon: DesktopOutlined, gradient: 'linear-gradient(135deg, #165DFF, #0E42D2)',
    route: '/hosts',
  },
  {
    key: 'online', label: '在线 Agent', value: stats.value.onlineAgents,
    icon: CheckCircleOutlined, gradient: 'linear-gradient(135deg, #00B42A, #009A29)',
    route: '/hosts',
    change: stats.value.onlineAgentsChange,
  },
  {
    key: 'offline', label: '离线 Agent', value: stats.value.offlineAgents,
    icon: WarningOutlined, gradient: 'linear-gradient(135deg, #F53F3F, #CB2634)',
    route: '/hosts',
    change: stats.value.offlineAgentsChange,
  },
  {
    key: 'alerts', label: '待处理告警', value: stats.value.pendingAlerts,
    icon: WarningOutlined, gradient: 'linear-gradient(135deg, #FF7D00, #D25F00)',
    route: '/alerts',
  },
  {
    key: 'vulns', label: '未修复漏洞', value: stats.value.pendingVulnerabilities || 0,
    icon: BugOutlined, gradient: 'linear-gradient(135deg, #722ED1, #531DAB)',
    route: '/vulnerabilities',
  },
  {
    key: 'baseline', label: '待修复基线', value: stats.value.baselineFailCount,
    icon: SafetyOutlined, gradient: 'linear-gradient(135deg, #FADC19, #F7BA1E)',
    route: '/policies',
  },
])

// ========== 告警趋势折线图 ==========
const alertTrendOption = computed(() => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: '#fff',
    borderColor: '#E5E8EF',
    textStyle: { color: '#1D2129', fontSize: 12 },
  },
  legend: {
    bottom: 0,
    itemWidth: 12, itemHeight: 3,
    textStyle: { color: '#86909C', fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 48 },
  xAxis: {
    type: 'category',
    data: filteredTrendData.value.map(d => d.date),
    axisLine: { lineStyle: { color: '#E5E6EB' } },
    axisLabel: { color: '#86909C', fontSize: 11 },
    axisTick: { show: false },
  },
  yAxis: {
    type: 'value', minInterval: 1,
    axisLine: { show: false },
    axisLabel: { color: '#86909C', fontSize: 11 },
    splitLine: { lineStyle: { color: '#F2F3F5' } },
  },
  series: [
    { name: '紧急', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#F53F3F' }, data: filteredTrendData.value.map(d => d.critical ?? 0) },
    { name: '高危', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#FF7D00' }, data: filteredTrendData.value.map(d => d.high ?? 0) },
    { name: '中危', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#FADC19' }, data: filteredTrendData.value.map(d => d.medium ?? 0) },
    { name: '低危', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#165DFF' }, data: filteredTrendData.value.map(d => d.low ?? 0) },
  ],
}))

// ========== 安全风险分布雷达图 ==========
const roundPercent = (v?: number): number => Math.round((v ?? 0) * 10) / 10

const riskRadarOption = computed(() => {
  const values = [
    roundPercent(stats.value.baselineHostPercent),
    roundPercent(stats.value.hostAlertPercent),
    roundPercent(stats.value.vulnHostPercent),
    roundPercent(stats.value.edrAlertPercent),
    roundPercent(stats.value.virusHostPercent),
  ]
  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: '#fff', borderColor: '#E5E8EF',
      textStyle: { color: '#1D2129', fontSize: 12 },
      formatter: (params: any) => {
        const dims = ['基线不合规', '告警未处理', '漏洞未修复', 'EDR 风险', '病毒感染']
        return dims.map((name, i) => `${name}：<b>${params.value[i]}%</b>`).join('<br/>')
      },
    },
    radar: {
      center: ['50%', '54%'],
      radius: '65%',
      indicator: [
        { name: '基线不合规', max: 100 },
        { name: '告警未处理', max: 100 },
        { name: '漏洞未修复', max: 100 },
        { name: 'EDR 风险', max: 100 },
        { name: '病毒感染', max: 100 },
      ],
      axisName: { color: '#4E5969', fontSize: 12 },
      splitLine: { lineStyle: { color: '#F2F3F5' } },
      splitArea: { areaStyle: { color: ['rgba(255,255,255,0)', 'rgba(247,248,250,0.6)'] } },
      axisLine: { lineStyle: { color: '#E5E6EB' } },
    },
    series: [{
      type: 'radar',
      symbol: 'circle',
      symbolSize: 5,
      lineStyle: { color: '#F53F3F', width: 2 },
      areaStyle: { color: 'rgba(245, 63, 63, 0.18)' },
      itemStyle: { color: '#F53F3F' },
      data: [{ value: values, name: '主机风险占比 (%)' }],
    }],
  }
})

// ========== Agent 状态饼图 ==========
const agentPieOption = computed(() => ({
  tooltip: {
    trigger: 'item',
    backgroundColor: '#fff', borderColor: '#E5E8EF',
    textStyle: { color: '#1D2129', fontSize: 12 },
  },
  legend: {
    orient: 'vertical', right: 24, top: 'center',
    itemWidth: 10, itemHeight: 10, itemGap: 16,
    textStyle: { color: '#4E5969', fontSize: 13 },
  },
  series: [{
    type: 'pie', radius: ['55%', '80%'], center: ['35%', '50%'],
    avoidLabelOverlap: false,
    label: {
      show: true, position: 'center',
      formatter: () => `{total|${(stats.value.onlineAgents || 0) + (stats.value.offlineAgents || 0)}}\n{label|总计}`,
      rich: {
        total: { fontSize: 24, fontWeight: 700, color: '#1D2129', lineHeight: 32 },
        label: { fontSize: 12, color: '#86909C', lineHeight: 20 },
      },
    },
    itemStyle: { borderColor: '#fff', borderWidth: 2 },
    data: [
      { value: stats.value.onlineAgents || 0, name: '在线', itemStyle: { color: '#00B42A' } },
      { value: stats.value.offlineAgents || 0, name: '离线', itemStyle: { color: '#F53F3F' } },
    ],
  }],
}))

// ========== 工具函数 ==========
const severityColor = (s: string): string => {
  const map: Record<string, string> = {
    critical: '#F53F3F', high: '#FF7D00', medium: '#FADC19', low: '#165DFF',
  }
  return map[s] || '#86909C'
}

const formatRelativeTime = (dateStr: string): string => {
  const now = Date.now()
  const target = new Date(dateStr).getTime()
  const diff = now - target
  if (diff < 0) return '刚刚'
  const minutes = Math.floor(diff / 60000)
  if (minutes < 1) return '刚刚'
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days} 天前`
  return dateStr.slice(0, 10)
}
const getPassRateColor = (rate: number): string => {
  if (rate >= 90) return '#00B42A'
  if (rate >= 70) return '#FF7D00'
  return '#F53F3F'
}

// ========== 数据加载 ==========
const loadDashboardData = async () => {
  try {
    const data = await dashboardApi.getStats()
    stats.value = {
      ...data,
      baselineHardeningPercent: Math.round(data.baselineHardeningPercent || 0),
      baselineHostPercent: Math.round(data.baselineHostPercent ?? 0),
    }
    if (data.baselineRisks) {
      baselineRisks.value = data.baselineRisks.slice(0, 5)
    }
    // 告警趋势（后端统一返回 30 天，前端本地切片）
    alertTrendData.value = data.alertTrend ?? []
    // 最新告警
    latestAlerts.value = data.latestAlerts ?? []
  } catch (error) {
    console.error('加载 Dashboard 数据失败:', error)
  }
}

let refreshTimer: number | null = null

onMounted(() => {
  loadDashboardData()
  refreshTimer = window.setInterval(loadDashboardData, 30000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.dashboard-page {
  width: 100%;
}

.section-row {
  margin-bottom: 16px;
}

/* ========== 资产统计卡片 ========== */
.stat-card-item {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s, box-shadow 0.2s;
  height: 100%;
}

.stat-card-item:hover {
  border-color: #165DFF;
  box-shadow: 0 2px 8px rgba(22, 93, 255, 0.1);
}

.stat-card-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #FFFFFF;
  font-size: 18px;
  margin: 0 auto 12px;
}

.stat-card-value {
  font-size: 28px;
  font-weight: 700;
  color: #1D2129;
  line-height: 1.2;
}

.stat-card-label {
  font-size: 13px;
  color: #86909C;
  margin-top: 4px;
}

/* ========== Dashboard Card (Elkeid 风格) ========== */
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

.card-title {
  font-size: 14px;
  font-weight: 600;
  color: #1D2129;
}

.card-body {
  padding: 16px 20px;
}

.chart-container {
  display: flex;
  align-items: center;
  justify-content: center;
}

/* ========== 基线安全统计 ========== */
.compliance-ring {
  text-align: center;
  padding: 12px 0;
}

.compliance-label {
  font-size: 13px;
  color: #86909C;
  margin-top: 8px;
}

.compliance-detail {
  margin-top: 12px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid #F7F8FA;
}

.detail-row:last-child {
  border-bottom: none;
}

.detail-label {
  font-size: 13px;
  color: #4E5969;
}

.detail-value {
  font-size: 14px;
  font-weight: 500;
  color: #1D2129;
}

/* ========== 卡片变化趋势 ========== */
.stat-card-change {
  font-size: 12px;
  margin-top: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 2px;
}

.change-up {
  color: #F53F3F;
}

.change-down {
  color: #00B42A;
}

/* ========== 卡片链接 ========== */
.card-link {
  font-size: 13px;
  color: #165DFF;
  cursor: pointer;
}

.card-link:hover {
  color: #0E42D2;
}

/* ========== 最新告警列表 ========== */
.latest-alerts-body {
  padding: 8px 20px 16px;
}

.alert-list {
  display: flex;
  flex-direction: column;
}

.alert-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 0;
  border-bottom: 1px solid #F7F8FA;
  cursor: pointer;
  transition: background 0.2s;
}

.alert-item:last-child {
  border-bottom: none;
}

.alert-item:hover {
  background: #F7F8FA;
  margin: 0 -12px;
  padding-left: 12px;
  padding-right: 12px;
  border-radius: 4px;
}

.alert-severity-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  margin-top: 6px;
}

.alert-main {
  flex: 1;
  min-width: 0;
}

.alert-title {
  font-size: 13px;
  color: #1D2129;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  line-height: 20px;
}

.alert-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 2px;
  font-size: 12px;
  color: #86909C;
}

.alert-host {
  max-width: 120px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
