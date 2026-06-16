<template>
  <div class="category-report report-print-ready">
    <ReportHeader
      title="EDR 检测专项报告"
      :subtitle="`${report.meta.onlineHosts} 台主机 · ${report.meta.enabledRules} 条规则启用`"
      :period="report.meta.period"
      :report-id="report.meta.reportID"
      :generated-at="report.meta.generatedAt"
    />
    <div class="export-bar no-print">
      <a-button type="primary" :loading="exporting" @click="exportPDF">
        <template #icon><FilePdfOutlined /></template>
        导出 PDF
      </a-button>
      <span class="export-bar__hint">服务端 Chromium 渲染 · 可搜索矢量文本</span>
    </div>
    <a-spin :spinning="loading">
      <!-- 元数据 -->
      <a-row :gutter="[16, 16]" class="stats-overview">
        <a-col :xs="12" :sm="8" :lg="{ span: 4, offset: 2 }">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="在线主机" :value="report.meta.onlineHosts" :value-style="{ color: '#22C55E' }" />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="启用规则" :value="report.meta.enabledRules" :value-style="{ color: '#3B82F6' }">
              <template #suffix>/ {{ report.meta.totalRules }}</template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="告警总数" :value="report.summary.totalAlerts" :value-style="{ color: '#F59E0B' }" />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="活跃告警" :value="report.summary.activeAlerts" :value-style="{ color: '#EF4444' }" />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="已忽略" :value="report.summary.ignoredAlerts" :value-style="{ color: '#86909C' }" />
          </a-card>
        </a-col>
      </a-row>

      <a-row :gutter="[16, 16]" class="stats-overview">
        <a-col :xs="12" :sm="8" :lg="{ span: 4, offset: 2 }">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="受影响主机" :value="report.summary.affectedHosts" :value-style="{ color: '#722ed1' }" />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="攻击故事线" :value="report.summary.totalStories" :value-style="{ color: '#3B82F6' }" />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic title="高危故事线" :value="report.summary.highRiskStories" :value-style="{ color: '#EF4444' }" />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="环比"
              :value="Math.abs(report.trend.growthPercent)"
              :precision="1"
              suffix="%"
              :value-style="{ color: trendColor }"
            >
              <template #prefix>{{ trendArrow }}</template>
            </a-statistic>
          </a-card>
        </a-col>
      </a-row>

      <!-- 严重程度 + Category 分布 -->
      <a-row :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :xs="24" :lg="12">
          <a-card title="严重程度分布" :bordered="false">
            <VChart theme="mxsec" :option="severityOption" style="height: 320px" autoresize />
          </a-card>
        </a-col>
        <a-col :xs="24" :lg="12">
          <a-card title="MITRE ATT&CK 战术分布" :bordered="false">
            <VChart theme="mxsec" :option="tacticOption" style="height: 320px" autoresize />
          </a-card>
        </a-col>
      </a-row>

      <!-- Top 触发规则 + Top 主机 -->
      <a-row :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :xs="24" :lg="12">
          <a-card title="Top 10 触发规则" :bordered="false">
            <a-table
              :columns="ruleColumns"
              :data-source="report.topRules"
              :pagination="false"
              size="small"
              row-key="title"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <a-tag :color="severityColors[record.severity] || 'default'">
                    {{ severityLabelMap[record.severity] || record.severity }}
                  </a-tag>
                </template>
              </template>
            </a-table>
          </a-card>
        </a-col>
        <a-col :xs="24" :lg="12">
          <a-card title="Top 10 受影响主机" :bordered="false">
            <a-table
              :columns="hostColumns"
              :data-source="report.topHosts"
              :pagination="false"
              size="small"
              row-key="host_id"
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- 原始事件量（ClickHouse） -->
      <a-row v-if="report.rawEventStats?.available" :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :span="24">
          <a-card :bordered="false">
            <template #title>
              <span>原始事件量统计</span>
              <a-tag color="cyan" style="margin-left: 8px">ClickHouse 真实数据</a-tag>
            </template>
            <a-row :gutter="[16, 16]">
              <a-col :xs="12" :md="6">
                <a-statistic title="总事件数" :value="report.rawEventStats.totalEvents" :value-style="{ color: '#3B82F6' }" />
              </a-col>
              <a-col :xs="12" :md="6">
                <a-statistic title="活跃主机" :value="report.rawEventStats.uniqueHosts" :value-style="{ color: '#22C55E' }" />
              </a-col>
              <a-col :xs="12" :md="6">
                <a-statistic
                  title="平均/主机"
                  :value="report.rawEventStats.uniqueHosts > 0
                    ? Math.round(report.rawEventStats.totalEvents / report.rawEventStats.uniqueHosts)
                    : 0"
                  :value-style="{ color: '#F59E0B' }"
                />
              </a-col>
              <a-col :xs="12" :md="6">
                <a-statistic
                  title="告警转化率"
                  :value="alertConversionRate"
                  :precision="2"
                  suffix="%"
                  :value-style="{ color: '#722ed1' }"
                />
              </a-col>
            </a-row>
            <a-row :gutter="[16, 16]" style="margin-top: 16px">
              <a-col :xs="24" :lg="12">
                <div style="font-weight: 500; margin-bottom: 8px">事件类型分布</div>
                <VChart theme="mxsec" :option="eventTypeOption" style="height: 280px" autoresize />
              </a-col>
              <a-col :xs="24" :lg="12">
                <div style="font-weight: 500; margin-bottom: 8px">事件量趋势（小时）</div>
                <VChart theme="mxsec" :option="eventTrendOption" style="height: 280px" autoresize />
              </a-col>
            </a-row>
            <a-row :gutter="[16, 16]" style="margin-top: 16px">
              <a-col :xs="24" :lg="12">
                <div style="font-weight: 500; margin-bottom: 8px">Top 10 主机（按事件量）</div>
                <a-table
                  :columns="rawHostColumns"
                  :data-source="report.rawEventStats.topHostsByEvent"
                  :pagination="false"
                  size="small"
                  row-key="host_id"
                />
              </a-col>
              <a-col :xs="24" :lg="12">
                <div style="font-weight: 500; margin-bottom: 8px">Top 10 进程</div>
                <a-table
                  :columns="exeColumns"
                  :data-source="report.rawEventStats.topExe"
                  :pagination="false"
                  size="small"
                  row-key="exe"
                />
              </a-col>
            </a-row>
          </a-card>
        </a-col>
      </a-row>

      <!-- 自动响应 + IOC + 规则有效性 -->
      <a-row :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :xs="24" :lg="8">
          <a-card title="自动响应执行" :bordered="false">
            <a-row :gutter="[12, 12]">
              <a-col :span="24">
                <a-statistic title="累计动作" :value="report.autoResponseStats?.total || 0" :value-style="{ color: '#722ed1' }" />
              </a-col>
              <a-col :span="8">
                <a-statistic title="网络封禁" :value="report.autoResponseStats?.networkBlocks || 0" :value-style="{ fontSize: '18px' }" />
              </a-col>
              <a-col :span="8">
                <a-statistic title="主机隔离" :value="report.autoResponseStats?.hostIsolations || 0" :value-style="{ fontSize: '18px' }" />
              </a-col>
              <a-col :span="8">
                <a-statistic title="进程查杀" :value="report.autoResponseStats?.processKills || 0" :value-style="{ fontSize: '18px' }" />
              </a-col>
            </a-row>
          </a-card>
        </a-col>
        <a-col :xs="24" :lg="8">
          <a-card title="IOC / 内存威胁" :bordered="false">
            <a-row :gutter="[12, 12]">
              <a-col :span="12">
                <a-statistic title="IOC 快照" :value="report.iocStats?.iocSnapshots || 0" :value-style="{ color: '#0891b2' }" />
              </a-col>
              <a-col :span="12">
                <a-statistic title="内存威胁" :value="report.iocStats?.memoryThreats || 0" :value-style="{ color: '#EF4444' }" />
              </a-col>
            </a-row>
            <div v-if="report.iocStats?.topIOCTypes?.length" style="margin-top: 12px">
              <div style="font-size: 12px; color: rgba(0,0,0,0.45); margin-bottom: 6px">Top 技术</div>
              <a-tag v-for="t in report.iocStats.topIOCTypes" :key="t.technique" color="red" style="margin-bottom: 4px">
                {{ t.technique }} ({{ t.count }})
              </a-tag>
            </div>
          </a-card>
        </a-col>
        <a-col :xs="24" :lg="8">
          <a-card title="规则有效性" :bordered="false">
            <a-statistic title="命中率" :value="report.ruleEfficacy?.hitRate || 0" :precision="1" suffix="%" :value-style="{ color: '#22C55E' }" />
            <a-progress
              :percent="Math.round(report.ruleEfficacy?.hitRate || 0)"
              :stroke-color="(report.ruleEfficacy?.hitRate || 0) > 50 ? '#22C55E' : '#F59E0B'"
              style="margin-top: 8px"
            />
            <div style="font-size: 12px; color: rgba(0,0,0,0.45); margin-top: 8px">
              {{ report.ruleEfficacy?.hitRules || 0 }} / {{ report.ruleEfficacy?.enabledRules || 0 }} 启用规则有命中
              · {{ report.ruleEfficacy?.zeroHitRules || 0 }} 条零命中
            </div>
          </a-card>
        </a-col>
      </a-row>

      <!-- 0 命中规则建议下线列表 -->
      <a-row v-if="report.ruleEfficacy?.topZeroHit?.length" :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :span="24">
          <a-card title="零命中规则（建议复核或下线）" :bordered="false">
            <a-table
              :columns="zeroHitColumns"
              :data-source="report.ruleEfficacy.topZeroHit"
              :pagination="false"
              size="small"
              row-key="id"
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- 改进建议 -->
      <a-row v-if="report.improvements?.length" :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :span="24">
          <a-card title="改进建议" :bordered="false">
            <a-list :data-source="report.improvements" size="small">
              <template #renderItem="{ item, index }">
                <a-list-item>
                  <span style="color: #722ed1; margin-right: 8px">{{ index + 1 }}.</span>
                  {{ item }}
                </a-list-item>
              </template>
            </a-list>
          </a-card>
        </a-col>
      </a-row>

      <!-- Top 高危故事线 + 误报抑制 -->
      <a-row :gutter="[16, 16]" style="margin-top: 16px">
        <a-col :xs="24" :lg="14">
          <a-card title="Top 5 高风险攻击故事线" :bordered="false">
            <a-table
              :columns="storyColumns"
              :data-source="report.topStories"
              :pagination="false"
              size="small"
              row-key="story_id"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <a-tag :color="severityColors[record.severity] || 'default'">
                    {{ severityLabelMap[record.severity] || record.severity }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'risk_score'">
                  <a-progress
                    :percent="record.risk_score"
                    :stroke-color="record.risk_score >= 70 ? '#EF4444' : record.risk_score >= 40 ? '#F59E0B' : '#3B82F6'"
                    size="small"
                  />
                </template>
              </template>
            </a-table>
          </a-card>
        </a-col>
        <a-col :xs="24" :lg="10">
          <a-card title="误报抑制统计" :bordered="false">
            <a-table
              :columns="suppressColumns"
              :data-source="report.suppressionStats"
              :pagination="false"
              size="small"
              row-key="reason"
            />
            <a-empty v-if="!report.suppressionStats.length" description="无抑制记录" />
          </a-card>
        </a-col>
      </a-row>
    </a-spin>
    <ReportFooter
      :report-id="report.meta.reportID"
      :generated-at="report.meta.generatedAt"
      watermark="MXSEC CONFIDENTIAL"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import {
  TitleComponent, TooltipComponent, LegendComponent, GridComponent,
} from 'echarts/components'
import type { EChartsOption } from 'echarts'
import type { Dayjs } from 'dayjs'
import { reportsApi, type EDRReport } from '@/api/reports'
import { FilePdfOutlined } from '@ant-design/icons-vue'
import ReportHeader from '@/components/report/ReportHeader.vue'
import ReportFooter from '@/components/report/ReportFooter.vue'

import { LineChart } from 'echarts/charts'
use([CanvasRenderer, PieChart, BarChart, LineChart, TitleComponent, TooltipComponent, LegendComponent, GridComponent])

const props = defineProps<{ dateRange: [Dayjs, Dayjs] }>()

const loading = ref(false)
const report = ref<EDRReport>({
  meta: { reportID: '', period: '', generatedAt: '', onlineHosts: 0, totalRules: 0, enabledRules: 0 },
  summary: { totalAlerts: 0, activeAlerts: 0, resolvedAlerts: 0, ignoredAlerts: 0, affectedHosts: 0, totalStories: 0, highRiskStories: 0 },
  severityDistribution: {},
  categoryDistribution: [],
  tacticDistribution: {},
  topRules: [],
  topHosts: [],
  topStories: [],
  suppressionStats: [],
  trend: { prevPeriodAlerts: 0, growthPercent: 0, direction: 'stable' },
  rawEventStats: { totalEvents: 0, uniqueHosts: 0, eventsByType: [], eventsByHour: [], topHostsByEvent: [], topExe: [], available: false },
  autoResponseStats: { networkBlocks: 0, hostIsolations: 0, processKills: 0, total: 0 },
  iocStats: { iocSnapshots: 0, memoryThreats: 0, topIOCTypes: [] },
  ruleEfficacy: { totalRules: 0, enabledRules: 0, hitRules: 0, zeroHitRules: 0, hitRate: 0, topZeroHit: [] },
  improvements: [],
})

const zeroHitColumns = [
  { title: 'ID', dataIndex: 'id', key: 'id', width: 80 },
  { title: '规则名', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '类别', dataIndex: 'category', key: 'category', width: 180 },
]

const alertConversionRate = computed(() => {
  const ev = report.value.rawEventStats?.totalEvents || 0
  const al = report.value.summary?.totalAlerts || 0
  return ev > 0 ? (al / ev) * 100 : 0
})

const eventTypeOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', left: 'left', textStyle: { fontSize: 11 } },
  series: [{
    name: '事件类型', type: 'pie', radius: ['40%', '70%'],
    itemStyle: { borderRadius: 6, borderColor: '#fff', borderWidth: 2 },
    label: { show: false }, labelLine: { show: false },
    data: (report.value.rawEventStats?.eventsByType || []).map(e => ({
      value: Number(e.count), name: e.event_type,
    })),
  }],
}))

const eventTrendOption = computed<EChartsOption>(() => {
  const data = report.value.rawEventStats?.eventsByHour || []
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map(d => d.hour.slice(5)),
      axisLabel: { rotate: 45, fontSize: 10, interval: Math.max(0, Math.floor(data.length / 12)) },
    },
    yAxis: { type: 'value' },
    series: [{
      name: '事件量', type: 'line', smooth: true,
      areaStyle: { opacity: 0.3 },
      data: data.map(d => Number(d.count)),
      itemStyle: { color: '#3B82F6' },
    }],
  }
})

const rawHostColumns = [
  { title: '主机', key: 'hostname', dataIndex: 'hostname', ellipsis: true },
  { title: '事件量', key: 'count', dataIndex: 'count', width: 110, align: 'right' as const },
]

const exeColumns = [
  { title: '进程路径', key: 'exe', dataIndex: 'exe', ellipsis: true },
  { title: '事件量', key: 'count', dataIndex: 'count', width: 110, align: 'right' as const },
]

const severityColors: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#0891b2',
}
const severityLabelMap: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危',
}

const tacticLabelMap: Record<string, string> = {
  initial_access: '初始访问', execution: '执行', persistence: '持久化',
  privilege_escalation: '权限提升', defense_evasion: '防御规避',
  credential_access: '凭据访问', discovery: '发现', lateral_movement: '横向移动',
  collection: '收集', exfiltration: '数据渗出', command_and_control: 'C2 通信',
  impact: '影响', other: '其他',
}

const trendColor = computed(() =>
  report.value.trend.direction === 'up' ? '#EF4444'
    : report.value.trend.direction === 'down' ? '#22C55E' : '#86909C'
)
const trendArrow = computed(() =>
  report.value.trend.direction === 'up' ? '↑'
    : report.value.trend.direction === 'down' ? '↓' : '→'
)

const severityOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', left: 'left' },
  series: [{
    name: '严重级别', type: 'pie', radius: ['40%', '70%'],
    itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
    data: (['critical', 'high', 'medium', 'low'] as const)
      .map(sev => ({
        value: report.value.severityDistribution[sev] || 0,
        name: severityLabelMap[sev],
        itemStyle: { color: severityColors[sev] },
      }))
      .filter(item => item.value > 0),
  }],
}))

const tacticOption = computed<EChartsOption>(() => {
  const entries = Object.entries(report.value.tacticDistribution)
    .filter(([, v]) => v > 0)
    .sort((a, b) => b[1] - a[1])
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: entries.map(([k]) => tacticLabelMap[k] || k),
      axisLabel: { rotate: 30, interval: 0 },
    },
    yAxis: { type: 'value' },
    series: [{
      name: '告警数', type: 'bar',
      data: entries.map(([, v]) => v),
      itemStyle: { color: '#722ed1' },
    }],
  }
})

const ruleColumns = [
  { title: '规则', key: 'title', dataIndex: 'title', ellipsis: true },
  { title: '级别', key: 'severity', width: 80 },
  { title: '命中', key: 'count', dataIndex: 'count', width: 80 },
]

const hostColumns = [
  { title: '主机', key: 'hostname', dataIndex: 'hostname', ellipsis: true },
  { title: '告警数', key: 'count', dataIndex: 'count', width: 90 },
]

const storyColumns = [
  { title: '主机', key: 'hostname', dataIndex: 'hostname', ellipsis: true, width: 200 },
  { title: '阶段', key: 'phase', dataIndex: 'phase', width: 130 },
  { title: '级别', key: 'severity', width: 70 },
  { title: '事件', key: 'event_count', dataIndex: 'event_count', width: 70 },
  { title: '告警', key: 'alert_count', dataIndex: 'alert_count', width: 70 },
  { title: '风险', key: 'risk_score', width: 130 },
]

const suppressColumns = [
  { title: '抑制原因', key: 'reason', dataIndex: 'reason', ellipsis: true },
  { title: '数量', key: 'count', dataIndex: 'count', width: 80 },
]

const loadData = async () => {
  loading.value = true
  try {
    const data = await reportsApi.getEDRReport({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    report.value = data
  } catch (e) {
    console.error('加载 EDR 报告失败:', e)
  } finally {
    loading.value = false
  }
}

const exporting = ref(false)
const exportPDF = async () => {
  exporting.value = true
  try {
    const blob = await reportsApi.exportEDRPDF({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `EDR-Report-${props.dateRange[1].format('YYYYMMDD')}.pdf`
    a.click()
    URL.revokeObjectURL(url)
    message.success('PDF 已生成')
  } catch (e: any) {
    console.error('PDF 导出失败:', e)
  } finally {
    exporting.value = false
  }
}

defineExpose({ loadData })

watch(() => props.dateRange, loadData, { deep: true })
onMounted(loadData)
</script>

<style scoped>
.category-report {
  padding: 0;
}
.stats-overview {
  margin-bottom: 0;
}
.stat-card {
  text-align: center;
}
.export-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  padding: 8px 16px;
  background: rgba(34, 197, 94, 0.06);
  border-left: 3px solid #22c55e;
  border-radius: 6px;

  &__hint {
    color: rgba(0, 0, 0, 0.45);
    font-size: 12px;
  }
}
</style>
