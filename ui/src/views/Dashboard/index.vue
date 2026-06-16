<template>
  <div class="dashboard-page">
    <!-- 页面标题 -->
    <div class="page-header">
      <h2>安全概览</h2>
      <span class="page-header-hint">实时监控平台安全态势</span>
    </div>

    <!-- Row 1: 安全评分 Banner -->
    <div class="security-banner" :style="{ background: bannerGradient }">
      <div class="banner-left">
        <div class="banner-label">安全态势评分</div>
        <div class="banner-score">
          <span class="score-value" :style="{ color: scoreColor }">{{ stats.securityScore ?? '--' }}</span>
          <span class="score-max">/100</span>
        </div>
        <div class="banner-level" :style="{ color: scoreColor }">{{ scoreLevel }}</div>
        <div v-if="(stats.criticalAlerts ?? 0) > 0" class="banner-warning">
          &#9888; {{ stats.criticalAlerts }} 个严重告警待处理
        </div>
        <div v-else class="banner-ok">&#10003; 系统运行正常</div>
      </div>
      <div class="banner-metrics">
        <div class="banner-metric">
          <div class="metric-value" :style="{ color: '#22C55E' }">{{ stats.onlineAgents || 0 }}</div>
          <div class="metric-label">在线主机</div>
        </div>
        <div class="banner-metric">
          <div class="metric-value" :style="{ color: '#EF4444' }">{{ (stats.pendingAlerts || 0).toLocaleString() }}</div>
          <div class="metric-label">告警</div>
        </div>
        <div class="banner-metric">
          <div class="metric-value" :style="{ color: '#F59E0B' }">{{ stats.storylineCount || 0 }}</div>
          <div class="metric-label">故事线</div>
        </div>
        <div class="banner-metric">
          <div class="metric-value" :style="{ color: '#06B6D4' }">{{ stats.pendingVulnerabilities || 0 }}</div>
          <div class="metric-label">待修漏洞</div>
        </div>
      </div>
    </div>

    <!-- Row 2: 4 列 StatCard -->
    <a-row :gutter="[12, 12]" class="section-row">
      <a-col :span="6">
        <StatCard
          title="威胁告警"
          :value="stats.pendingAlerts || 0"
          color="#3B82F6"
          :tags="alertTags"
          clickable
          @click="$router.push('/alerts')"
        />
      </a-col>
      <a-col :span="6">
        <StatCard
          title="Agent 在线率"
          :value="agentOnlinePercent"
          suffix="%"
          color="#06B6D4"
          :progress="agentOnlinePercent"
          :tags="agentTags"
          clickable
          @click="$router.push('/hosts')"
        />
      </a-col>
      <a-col :span="6">
        <StatCard
          title="基线合规率"
          :value="stats.baselineHardeningPercent || 0"
          suffix="%"
          color="#22C55E"
          :progress="stats.baselineHardeningPercent || 0"
          clickable
          @click="$router.push('/policies')"
        />
      </a-col>
      <a-col :span="6">
        <StatCard
          title="漏洞风险"
          :value="stats.pendingVulnerabilities || 0"
          color="#8B5CF6"
          clickable
          @click="$router.push('/vulnerabilities')"
        />
      </a-col>
    </a-row>

    <!-- Row 3: 告警趋势 (左) + 安全指数雷达 (中) + IOC 分布 (右) -->
    <a-row :gutter="[12, 12]" class="section-row">
      <a-col :span="10">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">告警趋势</span>
            <a-radio-group v-model:value="alertTrendRange" size="small">
              <a-radio-button value="7d">7 天</a-radio-button>
              <a-radio-button value="30d">30 天</a-radio-button>
            </a-radio-group>
          </div>
          <div class="card-body">
            <v-chart v-if="filteredTrendData.length > 0" :option="alertTrendOption" autoresize style="height: 260px" />
            <a-empty v-else description="暂无告警数据" />
          </div>
        </div>
      </a-col>
      <a-col :span="7">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">安全健康度</span>
          </div>
          <div class="card-body">
            <v-chart :option="riskRadarOption" autoresize style="height: 260px" />
          </div>
        </div>
      </a-col>
      <a-col :span="7">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">告警严重等级分布</span>
          </div>
          <div class="card-body">
            <v-chart :option="iocPieOption" autoresize style="height: 260px" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- Row 4: 攻击故事线 (左) + 实时事件流 (右) -->
    <a-row :gutter="[12, 12]" class="section-row">
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">最新攻击故事线</span>
            <a class="card-link" @click="$router.push('/storyline')">查看全部</a>
          </div>
          <div class="card-body list-body">
            <div v-if="storylineTop.length > 0" class="story-list">
              <div v-for="story in storylineTop" :key="story.story_id" class="story-item" @click="$router.push('/storyline')">
                <div class="story-main">
                  <span class="story-title">{{ story.title || story.story_id }}</span>
                  <span class="story-host">{{ story.hostname }}</span>
                </div>
                <span class="story-risk" :style="{ color: riskColor(story.risk_score), background: riskColor(story.risk_score) + '18' }">
                  risk {{ story.risk_score }}
                </span>
              </div>
            </div>
            <a-empty v-else description="暂无故事线" style="padding: 30px 0" />
          </div>
        </div>
      </a-col>
      <a-col :span="12">
        <div class="dashboard-card">
          <div class="card-header">
            <span class="card-title">实时事件流</span>
            <a class="card-link" @click="$router.push('/alerts')">查看全部</a>
          </div>
          <div class="card-body list-body">
            <div v-if="latestAlerts.length > 0" class="event-list">
              <div v-for="alert in latestAlerts" :key="alert.id" class="event-item" @click="$router.push(`/alerts/${alert.id}`)">
                <span class="event-dot" :style="{ background: severityColor(alert.severity) }" />
                <span class="event-time">{{ formatTime(alert.last_seen_at) }}</span>
                <span class="event-title">{{ alert.title }}</span>
                <span class="event-host">{{ alert.hostname || '未知' }}</span>
              </div>
            </div>
            <a-empty v-else description="暂无事件" style="padding: 30px 0" />
          </div>
        </div>
      </a-col>
    </a-row>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import StatCard from '@/components/StatCard.vue'
import { dashboardApi } from '@/api/dashboard'
import type { DashboardStats, AlertTrendItem, LatestAlert, StorylineTop } from '@/api/dashboard'
import { useChartTheme } from '@/composables/useChartTheme'
import { useThemeStore } from '@/stores/theme'

const { chartTheme } = useChartTheme()
const themeStore = useThemeStore()

// ========== 数据 ==========
const stats = ref<DashboardStats>({
  hosts: 0, clusters: 0, containers: 0,
  onlineAgents: 0, offlineAgents: 0,
  pendingAlerts: 0, pendingVulnerabilities: 0,
  vulnDbUpdateTime: '', baselineFailCount: 0,
  baselineHardeningPercent: 0,
})

const alertTrendRange = ref<'7d' | '30d'>('7d')
const alertTrendData = ref<AlertTrendItem[]>([])
const latestAlerts = ref<LatestAlert[]>([])
const storylineTop = ref<StorylineTop[]>([])

const filteredTrendData = computed(() => {
  const days = alertTrendRange.value === '7d' ? 7 : 30
  return alertTrendData.value.slice(-days)
})

// ========== StatCard 标签 ==========
const alertTags = computed(() => {
  const tags = []
  if (stats.value.criticalAlerts) tags.push({ label: `严重 ${stats.value.criticalAlerts}`, color: '#EF4444' })
  if (stats.value.highAlerts) tags.push({ label: `高危 ${stats.value.highAlerts}`, color: '#F59E0B' })
  return tags
})

// Agent 在线率 (替代 IOC 情报)
const agentOnlinePercent = computed(() => {
  const total = (stats.value.onlineAgents || 0) + (stats.value.offlineAgents || 0) || stats.value.hosts || 0
  const online = stats.value.onlineAgents || 0
  if (total === 0) return 0
  return Math.round((online / total) * 100)
})
const agentTags = computed(() => {
  const online = stats.value.onlineAgents || 0
  const total = (stats.value.onlineAgents || 0) + (stats.value.offlineAgents || 0) || stats.value.hosts || 0
  const offline = Math.max(0, total - online)
  const tags = [{ label: `在线 ${online}/${total}`, color: '#22C55E' }]
  if (offline > 0) tags.push({ label: `离线 ${offline}`, color: '#EF4444' })
  return tags
})

// ========== 告警趋势 ==========
const alertTrendOption = computed(() => ({
  tooltip: {
    trigger: 'axis',
    backgroundColor: chartTheme.value.tooltipBg,
    borderColor: chartTheme.value.tooltipBorder,
    textStyle: { color: chartTheme.value.tooltipText, fontSize: 12 },
  },
  legend: {
    bottom: 0,
    itemWidth: 12, itemHeight: 3,
    textStyle: { color: chartTheme.value.legendText, fontSize: 12 },
  },
  grid: { top: 16, right: 16, bottom: 36, left: 48 },
  xAxis: {
    type: 'category',
    data: filteredTrendData.value.map(d => d.date),
    axisLine: { lineStyle: { color: chartTheme.value.axisLine } },
    axisLabel: { color: chartTheme.value.axisLabel, fontSize: 11 },
    axisTick: { show: false },
  },
  yAxis: {
    type: 'value', minInterval: 1,
    axisLine: { show: false },
    axisLabel: { color: chartTheme.value.axisLabel, fontSize: 11 },
    splitLine: { lineStyle: { color: chartTheme.value.gridLine } },
  },
  series: [
    {
      name: '严重', type: 'line', smooth: true, symbol: 'none',
      lineStyle: { width: 2 }, itemStyle: { color: '#EF4444' },
      areaStyle: {
        color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [{ offset: 0, color: 'rgba(239,68,68,0.2)' }, { offset: 1, color: 'rgba(239,68,68,0)' }],
        },
      },
      data: filteredTrendData.value.map(d => d.critical ?? 0),
    },
    { name: '高危', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#F59E0B' }, data: filteredTrendData.value.map(d => d.high ?? 0) },
    { name: '中危', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#FADC19' }, data: filteredTrendData.value.map(d => d.medium ?? 0) },
    { name: '低危', type: 'line', smooth: true, symbol: 'none', lineStyle: { width: 2 }, itemStyle: { color: '#3B82F6' }, data: filteredTrendData.value.map(d => d.low ?? 0) },
  ],
}))

// ========== 告警严重等级分布环形图 (替代 IOC) ==========
const iocPieOption = computed(() => {
  const critical = stats.value.criticalAlerts || 0
  const high = stats.value.highAlerts || 0
  const medium = stats.value.mediumAlerts || 0
  const low = stats.value.lowAlerts || 0
  const total = critical + high + medium + low || stats.value.pendingAlerts || 0
  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: chartTheme.value.tooltipBg,
      borderColor: chartTheme.value.tooltipBorder,
      textStyle: { color: chartTheme.value.tooltipText, fontSize: 12 },
    },
    legend: {
      orient: 'vertical', right: 12, top: 'center',
      itemWidth: 10, itemHeight: 10, itemGap: 12,
      textStyle: { color: chartTheme.value.legendText, fontSize: 12 },
    },
    series: [{
      type: 'pie', radius: ['55%', '78%'], center: ['35%', '50%'],
      avoidLabelOverlap: false,
      label: {
        show: true, position: 'center',
        formatter: () => `{total|${formatCompact(total)}}\n{label|告警总数}`,
        rich: {
          total: { fontSize: 20, fontWeight: 700, color: chartTheme.value.tooltipText, lineHeight: 28 },
          label: { fontSize: 11, color: chartTheme.value.axisLabel, lineHeight: 18 },
        },
      },
      itemStyle: { borderColor: themeStore.isDark ? '#161B22' : '#FFFFFF', borderWidth: 2 },
      data: [
        { value: critical, name: `严重 ${critical.toLocaleString()}`, itemStyle: { color: '#EF4444' } },
        { value: high, name: `高危 ${high.toLocaleString()}`, itemStyle: { color: '#F59E0B' } },
        { value: medium, name: `中危 ${medium.toLocaleString()}`, itemStyle: { color: '#FADC19' } },
        { value: low, name: `低危 ${low.toLocaleString()}`, itemStyle: { color: '#3B82F6' } },
      ],
    }],
  }
})

// ========== 安全健康度雷达图 ==========
// 后端字段语义都是"出问题率（百分比，越大越糟）"。前端反转为"健康度"（100 - 风险率），
// 满六边形 = 5 维全 100% 健康，凹陷处 = 该维出问题率高。颜色绿色（健康）。
const healthScore = (v?: number): number => {
  const risk = Math.max(0, Math.min(100, v ?? 0))
  return Math.round((100 - risk) * 10) / 10
}

const riskRadarOption = computed(() => {
  const ct = chartTheme.value
  // 反转：值 = 健康度 (100 - 出问题率)
  const values = [
    healthScore(stats.value.baselineHostPercent),     // 基线合规率
    healthScore(stats.value.hostAlertPercent),        // 主机无告警率
    healthScore(stats.value.vulnHostPercent),         // 漏洞修复率
    healthScore(stats.value.detectionAlertPercent),   // 检测正常率
    healthScore(stats.value.virusHostPercent),        // 无病毒感染率
  ]
  return {
    tooltip: {
      trigger: 'item',
      backgroundColor: ct.tooltipBg,
      borderColor: ct.tooltipBorder,
      textStyle: { color: ct.tooltipText, fontSize: 12 },
      formatter: (params: any) => {
        const dims = ['基线合规', '主机无告警', '漏洞修复', '检测正常', '无病毒感染']
        return dims.map((name: string, i: number) => `${name}：<b>${params.value[i]}%</b>`).join('<br/>')
      },
    },
    radar: {
      center: ['50%', '54%'],
      radius: '65%',
      indicator: [
        { name: '基线合规', max: 100 },
        { name: '主机无告警', max: 100 },
        { name: '漏洞修复', max: 100 },
        { name: '检测正常', max: 100 },
        { name: '无病毒感染', max: 100 },
      ],
      axisName: { color: ct.axisLabel, fontSize: 11 },
      splitLine: { lineStyle: { color: ct.gridLine } },
      splitArea: { areaStyle: { color: ['transparent', themeStore.isDark ? 'rgba(30, 58, 95, 0.08)' : 'rgba(247,248,250,0.6)'] } },
      axisLine: { lineStyle: { color: ct.gridLine } },
    },
    series: [{
      type: 'radar',
      symbol: 'circle',
      symbolSize: 5,
      lineStyle: { color: '#22C55E', width: 2 },
      areaStyle: { color: 'rgba(34, 197, 94, 0.18)' },
      itemStyle: { color: '#22C55E' },
      data: [{ value: values, name: '安全健康度 (%)' }],
    }],
  }
})

// ========== 安全评分分档 ==========
// ≥80 健康(绿) / 60-79 亚健康(蓝) / 40-59 不健康(黄) / <40 危险(红)
// 后端 dashboard.go computeSecurityScore() 必返回 securityScore；undefined 仅在 API 失败/加载中出现 → 灰色"未知"
const scoreColor = computed(() => {
  const s = stats.value.securityScore
  if (s === undefined || s === null) return '#9CA3AF'
  if (s >= 80) return '#22C55E'
  if (s >= 60) return '#3B82F6'
  if (s >= 40) return '#F59E0B'
  return '#EF4444'
})

const scoreLevel = computed(() => {
  const s = stats.value.securityScore
  if (s === undefined || s === null) return '未知'
  if (s >= 80) return '健康'
  if (s >= 60) return '亚健康'
  if (s >= 40) return '需关注'
  return '高风险'
})

const bannerGradient = computed(() => {
  const s = stats.value.securityScore
  if (s === undefined || s === null) {
    return themeStore.isDark
      ? 'linear-gradient(135deg, #374151, #1F2937)'
      : 'linear-gradient(135deg, #6B7280, #4B5563)'
  }
  if (themeStore.isDark) {
    if (s >= 80) return 'linear-gradient(135deg, #14532D, #0D2818)'
    if (s >= 60) return 'linear-gradient(135deg, #1E3A5F, #0D2137)'
    if (s >= 40) return 'linear-gradient(135deg, #78350F, #451A03)'
    return 'linear-gradient(135deg, #7F1D1D, #450A0A)'
  }
  if (s >= 80) return 'linear-gradient(135deg, #16A34A, #15803D)'
  if (s >= 60) return 'linear-gradient(135deg, #2563EB, #1D4ED8)'
  if (s >= 40) return 'linear-gradient(135deg, #D97706, #B45309)'
  return 'linear-gradient(135deg, #DC2626, #B91C1C)'
})

// ========== 工具函数 ==========
const severityColor = (s: string): string => {
  const map: Record<string, string> = { critical: '#EF4444', high: '#F59E0B', medium: '#FADC19', low: '#3B82F6' }
  return map[s] || '#888'
}

const riskColor = (score: number): string => {
  if (score >= 4) return '#EF4444'
  if (score >= 3) return '#F59E0B'
  return '#3B82F6'
}

const formatTime = (dateStr: string): string => {
  if (!dateStr) return ''
  return dateStr.slice(11, 16) || dateStr.slice(0, 10)
}

const formatCompact = (n: number): string => {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}K`
  return n.toLocaleString()
}

// ========== 数据加载 ==========
const loadDashboardData = async () => {
  try {
    const data = await dashboardApi.getStats()
    stats.value = {
      ...data,
      baselineHardeningPercent: Math.round(data.baselineHardeningPercent || 0),
    }
    alertTrendData.value = data.alertTrend ?? []
    latestAlerts.value = data.latestAlerts ?? []
    storylineTop.value = data.storylineTop ?? []
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
  margin-bottom: 12px;
}

/* ========== 安全评分 Banner ========== */
.security-banner {
  border-radius: 12px;
  padding: 24px 28px;
  margin-bottom: 12px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: background 0.4s ease;
}

.banner-label {
  font-size: 14px;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.8);
  margin-bottom: 4px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
}

.banner-score {
  display: flex;
  align-items: baseline;
  gap: 4px;
}

.score-value {
  font-size: 52px;
  font-weight: 800;
  line-height: 1;
  text-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.score-max {
  font-size: 20px;
  font-weight: 600;
  color: rgba(255, 255, 255, 0.7);
}

.banner-level {
  font-size: 15px;
  font-weight: 700;
  margin-top: 4px;
  letter-spacing: 2px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
}

.banner-warning {
  font-size: 13px;
  font-weight: 500;
  color: #FCD34D;
  margin-top: 8px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
}

.banner-ok {
  font-size: 13px;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.8);
  margin-top: 8px;
}

.banner-metrics {
  display: flex;
  gap: 32px;
}

.banner-metric {
  text-align: center;
}

.metric-value {
  font-size: 28px;
  font-weight: 700;
  text-shadow: 0 1px 4px rgba(0, 0, 0, 0.2);
}

.metric-label {
  font-size: 12px;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.75);
  margin-top: 4px;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.15);
}

/* ========== Dashboard Card ========== */
.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 10px;
  height: 100%;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 20px;
  border-bottom: 1px solid var(--mxsec-border-light);
}

.card-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.card-body {
  padding: 16px 20px;
}

.card-link {
  font-size: 12px;
  color: var(--mxsec-primary);
  cursor: pointer;
}

.card-link:hover {
  color: var(--mxsec-primary-hover);
}

/* ========== 故事线列表 ========== */
.list-body {
  padding: 8px 20px 16px;
}

.story-list, .event-list {
  display: flex;
  flex-direction: column;
}

.story-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0;
  border-bottom: 1px solid var(--mxsec-border-light);
  cursor: pointer;
  transition: background 0.15s;
}

.story-item:last-child {
  border-bottom: none;
}

.story-item:hover {
  background: rgba(59, 130, 246, 0.04);
  margin: 0 -12px;
  padding-left: 12px;
  padding-right: 12px;
  border-radius: 6px;
}

.story-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  flex: 1;
}

.story-title {
  font-size: 13px;
  color: var(--mxsec-text-1);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.story-host {
  font-size: 11px;
  color: var(--mxsec-text-3);
}

.story-risk {
  padding: 2px 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  flex-shrink: 0;
  margin-left: 12px;
}

/* ========== 实时事件流 ========== */
.event-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid var(--mxsec-border-light);
  cursor: pointer;
  transition: background 0.15s;
}

.event-item:last-child {
  border-bottom: none;
}

.event-item:hover {
  background: rgba(59, 130, 246, 0.04);
  margin: 0 -12px;
  padding-left: 12px;
  padding-right: 12px;
  border-radius: 6px;
}

.event-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.event-time {
  font-size: 11px;
  color: var(--mxsec-text-3);
  min-width: 36px;
  font-family: monospace;
}

.event-title {
  font-size: 13px;
  color: var(--mxsec-text-1);
  flex: 1;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.event-host {
  font-size: 11px;
  color: var(--mxsec-text-3);
  flex-shrink: 0;
}
</style>
