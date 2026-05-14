<template>
  <div class="remediation-page">
    <div class="page-header">
      <h2>修复报告</h2>
      <span class="page-header-hint">漏洞修复进度概览与趋势分析</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ stats.totalVulns }}</div>
          <div class="stat-label">漏洞总数</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value success">{{ stats.patchedVulns }}</div>
          <div class="stat-label">已修复</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value danger">{{ stats.unpatchedVulns }}</div>
          <div class="stat-label">未修复</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value primary">{{ remediationRateText }}</div>
          <div class="stat-label">修复率</div>
        </div>
      </a-col>
    </a-row>

    <!-- MTTR 和修复率进度 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="24" :md="12">
        <div class="dashboard-card">
          <div class="card-header">修复进度</div>
          <div class="card-body">
            <a-progress
              :percent="stats.remediationRate"
              :stroke-color="progressColor"
              :format="(p: number) => `${p.toFixed(1)}%`"
            />
            <div class="mttr-info">
              <span class="mttr-label">平均修复时间 (MTTR)</span>
              <span class="mttr-value">{{ mttrText }}</span>
            </div>
          </div>
        </div>
      </a-col>
      <a-col :xs="24" :md="12">
        <div class="dashboard-card">
          <div class="card-header">按严重级别分布</div>
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
            </div>
            <a-empty v-if="!stats.bySeverity?.length" description="暂无数据" />
          </div>
        </div>
      </a-col>
    </a-row>

    <!-- 修复趋势图 -->
    <div class="dashboard-card section-row">
      <div class="card-header">
        修复趋势（近 30 天）
      </div>
      <div class="card-body">
        <div v-if="trend.length > 0" class="trend-chart">
          <div class="trend-legend">
            <span class="trend-legend-item"><span class="legend-dot discovered"></span> 新发现</span>
            <span class="trend-legend-item"><span class="legend-dot patched"></span> 已修复</span>
          </div>
          <div class="trend-bars">
            <div v-for="item in trend" :key="item.date" class="trend-bar-group" :title="`${item.date}\n新发现: ${item.discovered}\n已修复: ${item.patched}`">
              <div class="trend-bar discovered" :style="{ height: barHeight(item.discovered) }"></div>
              <div class="trend-bar patched" :style="{ height: barHeight(item.patched) }"></div>
            </div>
          </div>
        </div>
        <a-empty v-else description="暂无趋势数据" />
      </div>
    </div>

    <!-- Top 10 未修复最多的主机 -->
    <div class="dashboard-card section-row">
      <div class="card-header">未修复漏洞最多的主机 (Top 10)</div>
      <div class="card-body">
        <a-table
          :columns="hostColumns"
          :data-source="stats.topUnpatched ?? []"
          :pagination="false"
          size="small"
          row-key="hostId"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'host'">
              <RouterLink :to="`/hosts/${record.hostId}?tab=vulnerabilities`">
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
  { title: '主机', key: 'host', width: 200 },
  { title: 'IP', dataIndex: 'ip', width: 140 },
  { title: '漏洞总数', dataIndex: 'total', width: 100 },
  { title: '已修复', dataIndex: 'patched', width: 100 },
  { title: '未修复', key: 'unpatched', width: 100 },
  { title: '修复率', key: 'rate', width: 180 },
]

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

.stat-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}

.stat-value {
  font-size: 28px;
  font-weight: 700;
  color: #1D2129;
}

.stat-value.success { color: #52C41A; }
.stat-value.danger { color: #F53F3F; }
.stat-value.primary { color: #165DFF; }

.stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: #86909C;
}

.dashboard-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
}

.card-header {
  padding: 16px 20px;
  font-weight: 600;
  color: #1D2129;
  border-bottom: 1px solid #E5E8EF;
}

.card-body {
  padding: 20px;
}

.mttr-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 16px;
  padding: 12px;
  background: #F7F8FA;
  border-radius: 6px;
}

.mttr-label {
  font-size: 13px;
  color: #4E5969;
}

.mttr-value {
  font-size: 16px;
  font-weight: 600;
  color: #1D2129;
}

.severity-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.severity-label {
  width: 60px;
  flex-shrink: 0;
}

.severity-bar {
  flex: 1;
}

.trend-chart {
  width: 100%;
}

.trend-legend {
  display: flex;
  gap: 20px;
  margin-bottom: 12px;
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

.trend-bars {
  display: flex;
  align-items: flex-end;
  gap: 2px;
  height: 100px;
  padding: 10px 0;
}

.trend-bar-group {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1px;
  flex: 1;
  cursor: pointer;
}

.trend-bar {
  width: 100%;
  min-width: 4px;
  border-radius: 2px;
  transition: height 0.3s;
}

.trend-bar.discovered { background: #F53F3F; }
.trend-bar.patched { background: #52C41A; }

.text-danger { color: #F53F3F; font-weight: 600; }
</style>
