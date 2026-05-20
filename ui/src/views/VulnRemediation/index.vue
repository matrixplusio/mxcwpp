<template>
  <div class="remediation-page">
    <div class="page-header">
      <h2>修复报告</h2>
      <span class="page-header-hint">漏洞修复进度概览与趋势分析</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="stat-card-item">
          <div class="stat-card-icon" style="background: linear-gradient(135deg, #165DFF, #0E42D2)">
            <BugOutlined />
          </div>
          <div class="stat-card-value">{{ stats.totalVulns }}</div>
          <div class="stat-card-label">漏洞总数</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card-item">
          <div class="stat-card-icon" style="background: linear-gradient(135deg, #00B42A, #009A29)">
            <CheckCircleOutlined />
          </div>
          <div class="stat-card-value">{{ stats.patchedVulns }}</div>
          <div class="stat-card-label">已修复</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card-item">
          <div class="stat-card-icon" style="background: linear-gradient(135deg, #F53F3F, #CB2634)">
            <WarningOutlined />
          </div>
          <div class="stat-card-value">{{ stats.unpatchedVulns }}</div>
          <div class="stat-card-label">未修复</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card-item">
          <div class="stat-card-icon" style="background: linear-gradient(135deg, #722ED1, #531DAB)">
            <BarChartOutlined />
          </div>
          <div class="stat-card-value">{{ remediationRateText }}</div>
          <div class="stat-card-label">修复率</div>
        </div>
      </a-col>
    </a-row>

    <!-- MTTR 和修复率进度 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="24" :md="12">
        <div class="dashboard-card">
          <div class="card-header"><span class="card-title">修复进度</span></div>
          <div class="card-body">
            <div class="progress-ring-wrapper">
              <a-progress
                type="circle"
                :percent="stats.remediationRate"
                :size="140"
                :stroke-color="progressColor"
                :format="(p: number) => `${p.toFixed(1)}%`"
              />
            </div>
            <div class="progress-detail">
              <div class="detail-row">
                <span class="detail-label">平均修复时间 (MTTR)</span>
                <span class="detail-value" :class="{ 'text-success': stats.mttr > 0 && stats.mttr < 48 }">{{ mttrText }}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">已修复漏洞</span>
                <span class="detail-value text-success">{{ stats.patchedVulns }}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">待修复漏洞</span>
                <span class="detail-value text-danger">{{ stats.unpatchedVulns }}</span>
              </div>
            </div>
          </div>
        </div>
      </a-col>
      <a-col :xs="24" :md="12">
        <div class="dashboard-card">
          <div class="card-header"><span class="card-title">按严重级别分布</span></div>
          <div class="card-body">
            <div v-for="item in stats.bySeverity" :key="item.severity" class="severity-row">
              <div class="severity-label">
                <a-tag :color="severityColorMap[item.severity]" :bordered="false">
                  {{ severityTextMap[item.severity] || item.severity }}
                </a-tag>
              </div>
              <div class="severity-bar">
                <a-progress
                  :percent="item.total > 0 ? (item.patched / item.total) * 100 : 0"
                  :stroke-color="severityProgressColor[item.severity] || '#165DFF'"
                  size="small"
                  :format="() => `${item.patched}/${item.total}`"
                />
              </div>
              <div class="severity-count">{{ item.total }}</div>
            </div>
            <a-empty v-if="!stats.bySeverity?.length" description="暂无数据" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 修复趋势图 -->
    <div class="dashboard-card section-row">
      <div class="card-header">
        <span class="card-title">修复趋势（近 30 天）</span>
        <div class="trend-legend">
          <span class="trend-legend-item"><span class="legend-dot discovered"></span> 新发现</span>
          <span class="trend-legend-item"><span class="legend-dot patched"></span> 已修复</span>
        </div>
      </div>
      <div class="card-body">
        <div v-if="trend.length > 0" class="trend-chart">
          <div class="trend-bars">
            <div
              v-for="(item, idx) in trend"
              :key="item.date"
              class="trend-bar-group"
            >
              <a-tooltip>
                <template #title>
                  <div>{{ item.date }}</div>
                  <div>新发现: {{ item.discovered }}</div>
                  <div>已修复: {{ item.patched }}</div>
                </template>
                <div class="trend-bar-inner">
                  <div class="trend-bar discovered" :style="{ height: barHeight(item.discovered) }"></div>
                  <div class="trend-bar patched" :style="{ height: barHeight(item.patched) }"></div>
                </div>
              </a-tooltip>
              <span v-if="idx % 5 === 0" class="trend-date">{{ item.date.slice(5) }}</span>
              <span v-else class="trend-date"></span>
            </div>
          </div>
        </div>
        <a-empty v-else description="暂无趋势数据" />
      </div>
    </div>

    <!-- Top 10 未修复最多的主机 -->
    <div class="dashboard-card section-row">
      <div class="card-header">
        <span class="card-title">未修复漏洞最多的主机 (Top 10)</span>
      </div>
      <div class="card-body table-card-body">
        <a-table
          :columns="hostColumns"
          :data-source="stats.topUnpatched ?? []"
          :pagination="false"
          size="small"
          row-key="hostId"
        >
          <template #bodyCell="{ column, record, index }">
            <template v-if="column.key === 'rank'">
              <span class="rank-badge" :class="{ 'rank-top': index < 3 }">{{ index + 1 }}</span>
            </template>
            <template v-else-if="column.key === 'host'">
              <RouterLink :to="`/hosts/${record.hostId}?tab=vulnerabilities`" class="host-link">
                {{ record.hostname || record.hostId }}
              </RouterLink>
            </template>
            <template v-else-if="column.key === 'unpatched'">
              <span class="text-danger">{{ record.total - record.patched }}</span>
            </template>
            <template v-else-if="column.key === 'rate'">
              <a-progress
                :percent="record.total > 0 ? (record.patched / record.total) * 100 : 0"
                size="small"
                :stroke-color="getProgressColor(record.total > 0 ? (record.patched / record.total) * 100 : 0)"
                :format="(p: number) => `${p.toFixed(0)}%`"
              />
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { message } from 'ant-design-vue'
import { BugOutlined, CheckCircleOutlined, WarningOutlined, BarChartOutlined } from '@ant-design/icons-vue'
import { vulnerabilitiesApi } from '@/api/vulnerabilities'
import type { RemediationStats, DailyTrend } from '@/api/vulnerabilities'

const stats = ref<RemediationStats>({
  totalVulns: 0,
  patchedVulns: 0,
  unpatchedVulns: 0,
  ignoredVulns: 0,
  remediationRate: 0,
  mttr: 0,
  bySeverity: [],
  topUnpatched: [],
})

const trend = ref<DailyTrend[]>([])

const severityColorMap: Record<string, string> = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'blue',
}

const severityTextMap: Record<string, string> = {
  critical: '紧急',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const severityProgressColor: Record<string, string> = {
  critical: '#F53F3F',
  high: '#FF7D00',
  medium: '#FAAD14',
  low: '#165DFF',
}

const hostColumns = [
  { title: '#', key: 'rank', width: 50, align: 'center' as const },
  { title: '主机', key: 'host' },
  { title: 'IP', dataIndex: 'ip', width: 140 },
  { title: '漏洞总数', dataIndex: 'total', width: 100, align: 'center' as const },
  { title: '已修复', dataIndex: 'patched', width: 100, align: 'center' as const },
  { title: '未修复', key: 'unpatched', width: 100, align: 'center' as const },
  { title: '修复率', key: 'rate', width: 200 },
]

const getProgressColor = (percent: number) => {
  if (percent >= 80) return '#52C41A'
  if (percent >= 50) return '#FAAD14'
  return '#F53F3F'
}

const remediationRateText = computed(() => `${stats.value.remediationRate.toFixed(1)}%`)

const progressColor = computed(() => {
  const rate = stats.value.remediationRate
  if (rate >= 80) return '#52C41A'
  if (rate >= 50) return '#FAAD14'
  return '#F53F3F'
})

const mttrText = computed(() => {
  const hours = stats.value.mttr
  if (!hours || hours === 0) return '暂无数据'
  if (hours < 24) return `${hours.toFixed(1)} 小时`
  return `${(hours / 24).toFixed(1)} 天`
})

const maxTrendValue = computed(() => {
  let max = 1
  for (const item of trend.value) {
    if (item.discovered > max) max = item.discovered
    if (item.patched > max) max = item.patched
  }
  return max
})

const barHeight = (value: number) => {
  if (value === 0) return '2px'
  return `${Math.max(4, (value / maxTrendValue.value) * 80)}px`
}

const loadStats = async () => {
  try {
    stats.value = await vulnerabilitiesApi.getRemediationStats()
  } catch {
    message.error('加载修复统计失败')
  }
}

const loadTrend = async () => {
  try {
    trend.value = await vulnerabilitiesApi.getRemediationTrend(30)
  } catch {
    trend.value = []
  }
}

onMounted(() => {
  loadStats()
  loadTrend()
})
</script>

<style scoped>
.remediation-page { width: 100%; }
.section-row { margin-bottom: 16px; }

/* ========== 统计卡片（与 Dashboard 一致） ========== */
.stat-card-item {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
  text-align: center;
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

/* ========== Dashboard Card ========== */
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

/* ========== 修复进度（环形图 + 详情） ========== */
.progress-ring-wrapper {
  text-align: center;
  padding: 12px 0 16px;
}

.progress-detail {
  border-top: 1px solid #F2F3F5;
  padding-top: 12px;
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

/* ========== 严重级别分布 ========== */
.severity-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}

.severity-row:last-child {
  margin-bottom: 0;
}

.severity-label {
  width: 60px;
  flex-shrink: 0;
}

.severity-bar {
  flex: 1;
}

.severity-count {
  width: 40px;
  text-align: right;
  font-size: 13px;
  font-weight: 600;
  color: #1D2129;
  flex-shrink: 0;
}

/* ========== 趋势图 ========== */
.trend-legend {
  display: flex;
  gap: 20px;
}

.trend-legend-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #4E5969;
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.legend-dot.discovered { background: #F53F3F; }
.legend-dot.patched { background: #52C41A; }

.trend-chart {
  width: 100%;
}

.trend-bars {
  display: flex;
  align-items: flex-end;
  gap: 3px;
  height: 160px;
  padding: 10px 0 0;
  border-bottom: 1px solid #F2F3F5;
}

.trend-bar-group {
  display: flex;
  flex-direction: column;
  align-items: center;
  flex: 1;
  cursor: pointer;
}

.trend-bar-inner {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1px;
  width: 100%;
  height: 140px;
  justify-content: flex-end;
}

.trend-bar-group:hover .trend-bar {
  opacity: 0.8;
}

.trend-bar {
  width: 100%;
  min-width: 4px;
  max-width: 16px;
  border-radius: 2px 2px 0 0;
  transition: height 0.3s, opacity 0.2s;
}

.trend-bar.discovered { background: #F53F3F; }
.trend-bar.patched { background: #52C41A; }

.trend-date {
  font-size: 10px;
  color: #86909C;
  margin-top: 6px;
  white-space: nowrap;
  height: 14px;
}

/* ========== Top 10 表格 ========== */
.table-card-body {
  padding: 0;
}

.table-card-body :deep(.ant-table) {
  border-radius: 0 0 8px 8px;
}

.rank-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  color: #86909C;
  background: #F2F3F5;
}

.rank-badge.rank-top {
  color: #FFFFFF;
  background: linear-gradient(135deg, #165DFF, #0E42D2);
}

.host-link {
  color: #165DFF;
}

.host-link:hover {
  color: #0E42D2;
  text-decoration: underline;
}

/* ========== 通用 ========== */
.text-danger { color: #F53F3F; font-weight: 600; }
.text-success { color: #00B42A; font-weight: 600; }
</style>
