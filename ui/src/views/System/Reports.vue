<template>
  <div class="reports-page report-print-ready">
    <div class="page-header no-print">
      <h2>统计报表</h2>
      <div class="header-actions">
        <a-range-picker
          v-model:value="dateRange"
          :presets="datePresets"
          format="YYYY-MM-DD"
          @change="handleDateRangeChange"
        />
        <a-button type="primary" @click="handleRefresh" :loading="loading">
          <template #icon><ReloadOutlined /></template>
          刷新数据
        </a-button>
      </div>
    </div>

    <a-tabs v-model:activeKey="activeTab" class="reports-tabs no-print">
      <a-tab-pane key="overview" tab="安全总览" />
      <a-tab-pane key="antivirus" tab="病毒查杀" />
      <a-tab-pane key="vulnerability" tab="漏洞管理" />
      <a-tab-pane key="kube" tab="容器安全" />
      <a-tab-pane key="edr" tab="EDR 检测" />
    </a-tabs>

    <!-- 统一品牌封面 (各 tab 共享) -->
    <ReportHeader
      v-if="activeTab !== 'edr'"
      :title="tabTitle"
      :subtitle="tabSubtitle"
      :period="dateRangeLabel"
      :report-id="`mxsec-${activeTab}-${dateRange[1]?.format('YYYYMMDD')}`"
      :generated-at="generatedAtLabel"
    />

    <template v-if="activeTab === 'overview'">
    <!-- 统计概览卡片 -->
    <a-row :gutter="[16, 16]" class="stats-overview">
      <a-col :xs="24" :sm="12" :md="6" :lg="6">
        <a-card :bordered="false" class="stat-card stat-hosts">
          <div class="stat-card-inner">
            <div class="stat-icon-bg">
              <DesktopOutlined />
            </div>
            <a-statistic
              title="主机总数"
              :value="reportStats.hostStats?.total || 0"
              :value-style="{ color: '#3B82F6' }"
            />
          </div>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6">
        <a-card :bordered="false" class="stat-card stat-baseline">
          <div class="stat-card-inner">
            <div class="stat-icon-bg">
              <SafetyCertificateOutlined />
            </div>
            <a-statistic
              title="基线检查总数"
              :value="reportStats.baselineStats?.totalChecks || 0"
              :value-style="{ color: '#22C55E' }"
            />
          </div>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6">
        <a-card :bordered="false" class="stat-card stat-policy">
          <div class="stat-card-inner">
            <div class="stat-icon-bg">
              <FileProtectOutlined />
            </div>
            <a-statistic
              title="策略总数"
              :value="reportStats.policyStats?.total || 0"
              :value-style="{ color: '#722ed1' }"
            />
          </div>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="12" :md="6" :lg="6">
        <a-card :bordered="false" class="stat-card stat-task">
          <div class="stat-card-inner">
            <div class="stat-icon-bg">
              <ThunderboltOutlined />
            </div>
            <a-statistic
              title="任务总数"
              :value="reportStats.taskStats?.total || 0"
              :value-style="{ color: '#D25F00' }"
            />
          </div>
        </a-card>
      </a-col>
    </a-row>

    <!-- 第一行图表 -->
    <a-row :gutter="[16, 16]" class="charts-row">
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="主机状态分布" :bordered="false" class="chart-card">
          <v-chart
            :option="hostStatusChartOption"
            :loading="loading"
            style="height: 300px"
            autoresize
          />
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="主机风险分布" :bordered="false" class="chart-card">
          <v-chart
            :option="hostRiskChartOption"
            :loading="loading"
            style="height: 300px"
            autoresize
          />
        </a-card>
      </a-col>
    </a-row>

    <!-- 第二行图表 -->
    <a-row :gutter="[16, 16]" class="charts-row">
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="基线检查结果统计" :bordered="false" class="chart-card">
          <v-chart
            :option="baselineResultChartOption"
            :loading="loading"
            style="height: 300px"
            autoresize
          />
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="基线检查严重级别分布" :bordered="false" class="chart-card">
          <v-chart
            :option="severityChartOption"
            :loading="loading"
            style="height: 300px"
            autoresize
          />
        </a-card>
      </a-col>
    </a-row>

    <!-- 第三行图表 -->
    <a-row :gutter="[16, 16]" class="charts-row">
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="操作系统分布" :bordered="false" class="chart-card">
          <v-chart
            :option="osDistributionChartOption"
            :loading="loading"
            style="height: 300px"
            autoresize
          />
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="基线检查类别分布" :bordered="false" class="chart-card">
          <v-chart
            :option="categoryChartOption"
            :loading="loading"
            style="height: 300px"
            autoresize
          />
        </a-card>
      </a-col>
    </a-row>

    <!-- 第四行：趋势图 -->
    <a-row :gutter="[16, 16]" class="charts-row">
      <a-col :xs="24" :sm="24" :md="24" :lg="24">
        <a-card title="基线得分趋势" :bordered="false" class="chart-card">
          <v-chart
            v-if="baselineScoreTrend.dates.length > 0"
            :option="baselineScoreTrendOption"
            :loading="loading"
            style="height: 400px"
            autoresize
          />
          <a-empty
            v-else
            description="暂无数据（后端 API 尚未实现）"
            style="height: 400px; display: flex; align-items: center; justify-content: center"
          />
        </a-card>
      </a-col>
    </a-row>

    <!-- 第五行：检查结果趋势 -->
    <a-row :gutter="[16, 16]" class="charts-row">
      <a-col :xs="24" :sm="24" :md="24" :lg="24">
        <a-card title="检查结果趋势" :bordered="false" class="chart-card">
          <v-chart
            v-if="checkResultTrend.dates.length > 0"
            :option="checkResultTrendOption"
            :loading="loading"
            style="height: 400px"
            autoresize
          />
          <a-empty
            v-else
            description="暂无数据（后端 API 尚未实现）"
            style="height: 400px; display: flex; align-items: center; justify-content: center"
          />
        </a-card>
      </a-col>
    </a-row>

    <!-- 第六行：Top 列表 -->
    <a-row :gutter="[16, 16]" class="charts-row">
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="Top 10 失败检查项" :bordered="false" class="list-card">
          <template #extra>
            <a-button type="link" size="small" @click="goToTaskReport">
              查看详情
            </a-button>
          </template>
          <a-spin :spinning="loadingTopLists">
            <a-table
              v-if="topFailedRules.length > 0"
              :columns="failedRulesColumns"
              :data-source="topFailedRules"
              :pagination="false"
              row-key="rule_id"
              size="small"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <a-tag :color="getSeverityColor(record.severity)">
                    {{ getSeverityLabel(record.severity) }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'affected_hosts'">
                  <span style="color: #EF4444; font-weight: 500">
                    {{ record.affected_hosts }} 台
                  </span>
                </template>
              </template>
            </a-table>
            <a-empty v-else description="暂无失败检查项" />
          </a-spin>
        </a-card>
      </a-col>
      <a-col :xs="24" :sm="24" :md="12" :lg="12">
        <a-card title="Top 10 风险主机" :bordered="false" class="list-card">
          <template #extra>
            <a-button type="link" size="small" @click="goToHosts">
              查看详情
            </a-button>
          </template>
          <a-spin :spinning="loadingTopLists">
            <a-table
              v-if="topRiskHosts.length > 0"
              :columns="riskHostsColumns"
              :data-source="topRiskHosts"
              :pagination="false"
              row-key="host_id"
              size="small"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'hostname'">
                  <span>{{ record.hostname || record.host_id.slice(0, 8) }}</span>
                  <span v-if="record.ip" style="color: #86909C; margin-left: 4px; font-size: 12px">
                    ({{ record.ip }})
                  </span>
                </template>
                <template v-else-if="column.key === 'score'">
                  <a-progress
                    :percent="Math.round(record.score)"
                    :status="getScoreStatus(record.score)"
                    :stroke-color="getScoreColor(record.score)"
                    size="small"
                    style="width: 100px"
                  />
                </template>
                <template v-else-if="column.key === 'fails'">
                  <a-space :size="4">
                    <a-tag v-if="record.critical_count > 0" color="red">
                      严重 {{ record.critical_count }}
                    </a-tag>
                    <a-tag v-if="record.high_count > 0" color="orange">
                      高危 {{ record.high_count }}
                    </a-tag>
                  </a-space>
                </template>
                <template v-else-if="column.key === 'action'">
                  <a-button type="link" size="small" @click="goToHostDetail(record.host_id)">
                    详情
                  </a-button>
                </template>
              </template>
            </a-table>
            <a-empty v-else description="暂无风险主机" />
          </a-spin>
        </a-card>
      </a-col>
    </a-row>
    </template>

    <AntivirusReport
      v-else-if="activeTab === 'antivirus'"
      ref="antivirusRef"
      :date-range="dateRange"
    />
    <VulnerabilityReport
      v-else-if="activeTab === 'vulnerability'"
      ref="vulnerabilityRef"
      :date-range="dateRange"
    />
    <KubeReport
      v-else-if="activeTab === 'kube'"
      ref="kubeRef"
      :date-range="dateRange"
    />
    <EDRReport
      v-else-if="activeTab === 'edr'"
      ref="edrRef"
      :date-range="dateRange"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  ReloadOutlined,
  DesktopOutlined,
  SafetyCertificateOutlined,
  FileProtectOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons-vue'
import dayjs, { type Dayjs } from 'dayjs'
import {
  reportsApi,
  type ReportStats,
  type BaselineScoreTrend,
  type CheckResultTrend,
  type TopFailedRule,
  type TopRiskHost,
} from '@/api/reports'
import { hostsApi } from '@/api/hosts'
import { dashboardApi } from '@/api/dashboard'
import type { HostStatusDistribution } from '@/api/hosts'
import type { EChartsOption } from 'echarts'
import AntivirusReport from './reports/AntivirusReport.vue'
import VulnerabilityReport from './reports/VulnerabilityReport.vue'
import KubeReport from './reports/KubeReport.vue'
import EDRReport from './reports/EDRReport.vue'
import ReportHeader from '@/components/report/ReportHeader.vue'

// 报表专用风险分布接口
interface ReportRiskDistribution {
  host_container_alerts: number
  app_runtime_alerts: number
  high_exploitable_vulns: number
  virus_files: number
  high_risk_baselines: number
}

const route = useRoute()
const router = useRouter()
const loading = ref(false)
const loadingTopLists = ref(false)

const validTabs = ['overview', 'antivirus', 'vulnerability', 'kube', 'edr']
const initialTab = validTabs.includes(route.query.tab as string) ? (route.query.tab as string) : 'overview'
const activeTab = ref<string>(initialTab)

watch(activeTab, (val) => {
  router.replace({ query: { ...route.query, tab: val } })
})
const dateRange = ref<[Dayjs, Dayjs]>([
  dayjs().subtract(7, 'day'),
  dayjs()
])

// 报告封面动态标题
const tabTitleMap: Record<string, string> = {
  overview: '安全总览专项报告',
  antivirus: '病毒查杀专项报告',
  vulnerability: '漏洞管理专项报告',
  kube: '容器安全专项报告',
  edr: 'EDR 检测专项报告',
}
const tabSubtitleMap: Record<string, string> = {
  overview: '主机风险 / 告警 / 趋势综合视图',
  antivirus: '威胁检出 · 隔离 · 处置动作',
  vulnerability: 'CVE / 主机 / 组件多维度分析',
  kube: '集群基线 / Pod / 工作负载合规',
  edr: '攻击故事线 / MITRE 战术 / 规则有效性',
}
const tabTitle = computed(() => tabTitleMap[activeTab.value] || '统计报表')
const tabSubtitle = computed(() => tabSubtitleMap[activeTab.value] || '')
const dateRangeLabel = computed(() => {
  const [s, e] = dateRange.value || []
  if (!s || !e) return ''
  return `${s.format('YYYY-MM-DD')} ~ ${e.format('YYYY-MM-DD')}`
})
const generatedAtLabel = computed(() => dayjs().format('YYYY-MM-DD HH:mm:ss'))

// 子组件 ref
const antivirusRef = ref<InstanceType<typeof AntivirusReport> | null>(null)
const vulnerabilityRef = ref<InstanceType<typeof VulnerabilityReport> | null>(null)
const kubeRef = ref<InstanceType<typeof KubeReport> | null>(null)
const edrRef = ref<InstanceType<typeof EDRReport> | null>(null)

const datePresets = [
  { label: '最近7天', value: [dayjs().subtract(7, 'day'), dayjs()] },
  { label: '最近30天', value: [dayjs().subtract(30, 'day'), dayjs()] },
  { label: '最近90天', value: [dayjs().subtract(90, 'day'), dayjs()] },
]

const reportStats = ref<ReportStats>({
  hostStats: {
    total: 0,
    online: 0,
    offline: 0,
    byOsFamily: {},
  },
  baselineStats: {
    totalChecks: 0,
    passed: 0,
    failed: 0,
    warning: 0,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    byCategory: {},
  },
  policyStats: {
    total: 0,
    enabled: 0,
    disabled: 0,
    avgPassRate: 0,
  },
  taskStats: {
    total: 0,
    completed: 0,
    running: 0,
    failed: 0,
  },
})

const hostStatusDistribution = ref<HostStatusDistribution>({
  running: 0,
  abnormal: 0,
  offline: 0,
  not_installed: 0,
  uninstalled: 0,
})

const hostRiskDistribution = ref<ReportRiskDistribution>({
  host_container_alerts: 0,
  app_runtime_alerts: 0,
  high_exploitable_vulns: 0,
  virus_files: 0,
  high_risk_baselines: 0,
})

const baselineScoreTrend = ref<BaselineScoreTrend>({
  dates: [],
  scores: [],
  passRates: [],
})

const checkResultTrend = ref<CheckResultTrend>({
  dates: [],
  passed: [],
  failed: [],
  warning: [],
})

// Top 列表数据
const topFailedRules = ref<TopFailedRule[]>([])
const topRiskHosts = ref<TopRiskHost[]>([])

// Top 失败检查项表格列定义
const failedRulesColumns = [
  { title: '检查项', key: 'title', dataIndex: 'title', ellipsis: true },
  { title: '级别', key: 'severity', width: 80 },
  { title: '类别', key: 'category', dataIndex: 'category', width: 100 },
  { title: '影响主机', key: 'affected_hosts', width: 100 },
]

// Top 风险主机表格列定义
const riskHostsColumns = [
  { title: '主机', key: 'hostname', ellipsis: true },
  { title: '得分', key: 'score', width: 130 },
  { title: '风险项', key: 'fails', width: 150 },
  { title: '操作', key: 'action', width: 70 },
]

// 主机状态分布图表配置
const hostStatusChartOption = computed<EChartsOption>(() => ({
  tooltip: {
    trigger: 'item',
    formatter: '{b}: {c} ({d}%)',
  },
  legend: {
    orient: 'vertical',
    left: 'left',
  },
  series: [
    {
      name: '主机状态',
      type: 'pie',
      radius: ['40%', '70%'],
      avoidLabelOverlap: false,
      itemStyle: {
        borderRadius: 10,
        borderColor: '#fff',
        borderWidth: 2,
      },
      label: {
        show: true,
        formatter: '{b}: {c}\n({d}%)',
      },
      emphasis: {
        label: {
          show: true,
          fontSize: 14,
          fontWeight: 'bold',
        },
      },
      data: [
        { value: hostStatusDistribution.value.running, name: '运行中', itemStyle: { color: '#22C55E' } },
        { value: hostStatusDistribution.value.abnormal, name: '异常', itemStyle: { color: '#F59E0B' } },
        { value: hostStatusDistribution.value.offline, name: '离线', itemStyle: { color: '#EF4444' } },
        { value: hostStatusDistribution.value.not_installed, name: '未安装', itemStyle: { color: '#86909C' } },
        { value: hostStatusDistribution.value.uninstalled, name: '已卸载', itemStyle: { color: '#d9d9d9' } },
      ].filter(item => item.value > 0),
    },
  ],
}))

// 主机风险分布图表配置
const hostRiskChartOption = computed<EChartsOption>(() => ({
  tooltip: {
    trigger: 'axis',
    axisPointer: {
      type: 'shadow',
    },
  },
  grid: {
    left: '3%',
    right: '4%',
    bottom: '3%',
    containLabel: true,
  },
  xAxis: {
    type: 'category',
    data: ['主机告警', '检测告警', '高危漏洞', '病毒文件', '高危基线'],
    axisLabel: {
      rotate: 45,
      interval: 0,
    },
  },
  yAxis: {
    type: 'value',
  },
  series: [
    {
      name: '风险主机数',
      type: 'bar',
      data: [
        hostRiskDistribution.value.host_container_alerts,
        hostRiskDistribution.value.app_runtime_alerts,
        hostRiskDistribution.value.high_exploitable_vulns,
        hostRiskDistribution.value.virus_files,
        hostRiskDistribution.value.high_risk_baselines,
      ],
      itemStyle: {
        color: '#EF4444',
      },
    },
  ],
}))

// 基线检查结果统计图表配置
const baselineResultChartOption = computed<EChartsOption>(() => ({
  tooltip: {
    trigger: 'item',
  },
  legend: {
    orient: 'vertical',
    left: 'left',
  },
  series: [
    {
      name: '检查结果',
      type: 'pie',
      radius: '60%',
      data: [
        { value: reportStats.value.baselineStats.passed, name: '通过', itemStyle: { color: '#22C55E' } },
        { value: reportStats.value.baselineStats.failed, name: '失败', itemStyle: { color: '#EF4444' } },
        { value: reportStats.value.baselineStats.warning, name: '警告', itemStyle: { color: '#F59E0B' } },
      ].filter(item => item.value > 0),
      emphasis: {
        itemStyle: {
          shadowBlur: 10,
          shadowOffsetX: 0,
          shadowColor: 'rgba(0, 0, 0, 0.5)',
        },
      },
    },
  ],
}))

// 严重级别分布图表配置
const severityChartOption = computed<EChartsOption>(() => ({
  tooltip: {
    trigger: 'axis',
    axisPointer: {
      type: 'shadow',
    },
  },
  grid: {
    left: '3%',
    right: '4%',
    bottom: '3%',
    containLabel: true,
  },
  xAxis: {
    type: 'category',
    data: ['严重', '高危', '中危', '低危'],
  },
  yAxis: {
    type: 'value',
  },
  series: [
    {
      name: '数量',
      type: 'bar',
      data: [
        reportStats.value.baselineStats.bySeverity.critical,
        reportStats.value.baselineStats.bySeverity.high,
        reportStats.value.baselineStats.bySeverity.medium,
        reportStats.value.baselineStats.bySeverity.low,
      ],
      itemStyle: {
        color: (params: any) => {
          const colors = ['#EF4444', '#ff7875', '#ffa940', '#ffc53d']
          return colors[params.dataIndex] || '#3B82F6'
        },
      },
    },
  ],
}))

// 操作系统分布图表配置
const osDistributionChartOption = computed<EChartsOption>(() => {
  const osData = Object.entries(reportStats.value.hostStats.byOsFamily).map(([name, value]) => ({
    name,
    value,
  }))
  
  return {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c} ({d}%)',
    },
    legend: {
      orient: 'vertical',
      left: 'left',
    },
    series: [
      {
        name: '操作系统',
        type: 'pie',
        radius: '60%',
        data: osData,
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)',
          },
        },
      },
    ],
  }
})

// 基线检查类别分布图表配置
const categoryChartOption = computed<EChartsOption>(() => {
  const categoryData = Object.entries(reportStats.value.baselineStats.byCategory).map(([name, value]) => ({
    name,
    value,
  }))
  
  return {
    tooltip: {
      trigger: 'item',
      formatter: '{b}: {c}',
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      data: categoryData.map(item => item.name),
      axisLabel: {
        rotate: 45,
        interval: 0,
      },
    },
    yAxis: {
      type: 'value',
    },
    series: [
      {
        name: '检查项数',
        type: 'bar',
        data: categoryData.map(item => item.value),
        itemStyle: {
          color: '#3B82F6',
        },
      },
    ],
  }
})

// 基线得分趋势图表配置
const baselineScoreTrendOption = computed<EChartsOption>(() => ({
  tooltip: {
    trigger: 'axis',
  },
  legend: {
    data: ['基线得分', '通过率'],
  },
  grid: {
    left: '3%',
    right: '4%',
    bottom: '3%',
    containLabel: true,
  },
  xAxis: {
    type: 'category',
    boundaryGap: false,
    data: baselineScoreTrend.value.dates,
  },
  yAxis: [
    {
      type: 'value',
      name: '得分',
      min: 0,
      max: 100,
      position: 'left',
    },
    {
      type: 'value',
      name: '通过率(%)',
      min: 0,
      max: 100,
      position: 'right',
    },
  ],
  series: [
    {
      name: '基线得分',
      type: 'line',
      yAxisIndex: 0,
      data: baselineScoreTrend.value.scores,
      smooth: true,
      itemStyle: {
        color: '#3B82F6',
      },
      areaStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 0,
          y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(24, 144, 255, 0.3)' },
            { offset: 1, color: 'rgba(24, 144, 255, 0.1)' },
          ],
        },
      },
    },
    {
      name: '通过率',
      type: 'line',
      yAxisIndex: 1,
      data: baselineScoreTrend.value.passRates,
      smooth: true,
      itemStyle: {
        color: '#22C55E',
      },
    },
  ],
}))

// 检查结果趋势图表配置
const checkResultTrendOption = computed<EChartsOption>(() => ({
  tooltip: {
    trigger: 'axis',
  },
  legend: {
    data: ['通过', '失败', '警告'],
  },
  grid: {
    left: '3%',
    right: '4%',
    bottom: '3%',
    containLabel: true,
  },
  xAxis: {
    type: 'category',
    boundaryGap: false,
    data: checkResultTrend.value.dates,
  },
  yAxis: {
    type: 'value',
  },
  series: [
    {
      name: '通过',
      type: 'line',
      stack: 'Total',
      data: checkResultTrend.value.passed,
      smooth: true,
      itemStyle: {
        color: '#22C55E',
      },
      areaStyle: {},
    },
    {
      name: '失败',
      type: 'line',
      stack: 'Total',
      data: checkResultTrend.value.failed,
      smooth: true,
      itemStyle: {
        color: '#EF4444',
      },
      areaStyle: {},
    },
    {
      name: '警告',
      type: 'line',
      stack: 'Total',
      data: checkResultTrend.value.warning,
      smooth: true,
      itemStyle: {
        color: '#F59E0B',
      },
      areaStyle: {},
    },
  ],
}))

const handleRefresh = () => {
  if (activeTab.value === 'overview') {
    refreshData()
  } else if (activeTab.value === 'antivirus') {
    antivirusRef.value?.refresh()
  } else if (activeTab.value === 'vulnerability') {
    vulnerabilityRef.value?.refresh()
  } else if (activeTab.value === 'kube') {
    kubeRef.value?.refresh()
  } else if (activeTab.value === 'edr') {
    edrRef.value?.loadData()
  }
}

const handleDateRangeChange = () => {
  if (activeTab.value === 'overview') {
    refreshData()
  }
  // 子组件通过 watch dateRange 自动刷新
}

// 辅助函数
const getSeverityColor = (severity: string): string => {
  const colors: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return colors[severity] || 'default'
}

const getSeverityLabel = (severity: string): string => {
  const labels: Record<string, string> = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
  }
  return labels[severity] || severity
}

const getScoreStatus = (score: number): 'success' | 'exception' | 'normal' => {
  if (score >= 80) return 'success'
  if (score < 60) return 'exception'
  return 'normal'
}

const getScoreColor = (score: number): string => {
  if (score >= 80) return '#22C55E'
  if (score >= 60) return '#F59E0B'
  return '#EF4444'
}

// 导航函数
const goToTaskReport = () => {
  router.push('/system/task-report')
}

const goToHosts = () => {
  router.push('/hosts')
}

const goToHostDetail = (hostId: string) => {
  router.push(`/hosts/${hostId}`)
}

// 加载 Top 列表数据
const loadTopLists = async () => {
  loadingTopLists.value = true
  try {
    const [failedRules, riskHosts] = await Promise.all([
      reportsApi.getTopFailedRules(10).catch(() => []),
      reportsApi.getTopRiskHosts(10).catch(() => []),
    ])
    topFailedRules.value = failedRules
    topRiskHosts.value = riskHosts
  } catch (error) {
    console.error('加载 Top 列表失败:', error)
  } finally {
    loadingTopLists.value = false
  }
}

const refreshData = async () => {
  loading.value = true
  try {
    const startTime = dateRange.value[0].format('YYYY-MM-DD')
    const endTime = dateRange.value[1].format('YYYY-MM-DD')

    // 并行加载所有数据
    const [
      stats,
      statusDist,
      riskDist,
      scoreTrend,
      resultTrend,
    ] = await Promise.all([
      reportsApi.getStats({ start_time: startTime, end_time: endTime }).catch(() => null),
      hostsApi.getStatusDistribution().catch(() => null),
      hostsApi.getRiskDistribution().catch(() => null),
      reportsApi.getBaselineScoreTrend({
        start_time: startTime,
        end_time: endTime,
        interval: 'day',
      }).catch(() => null),
      reportsApi.getCheckResultTrend({
        start_time: startTime,
        end_time: endTime,
        interval: 'day',
      }).catch(() => null),
    ])

    if (stats) {
      reportStats.value = stats
    }

    if (statusDist) {
      hostStatusDistribution.value = statusDist
    }

    // TODO: hostRiskDistribution 使用不同的数据结构，需要从专用报表 API 获取
    // riskDist 是 HostRiskDistribution 类型（critical/high/medium/low）
    // hostRiskDistribution 是 ReportRiskDistribution 类型（host_container_alerts等）
    if (riskDist) {
      // 暂时跳过，等待后端实现报表专用 API
      console.log('Risk distribution loaded:', riskDist)
    }

    if (scoreTrend) {
      baselineScoreTrend.value = scoreTrend
    }

    if (resultTrend) {
      checkResultTrend.value = resultTrend
    }

    // 如果没有报表统计数据，尝试从 Dashboard API 获取基础数据
    if (!stats) {
      try {
        const dashboardStats = await dashboardApi.getStats()
        reportStats.value.hostStats.total = dashboardStats.hosts
        reportStats.value.hostStats.online = dashboardStats.onlineAgents
        reportStats.value.hostStats.offline = dashboardStats.offlineAgents
        reportStats.value.baselineStats.totalChecks = dashboardStats.baselineFailCount || 0
      } catch (error) {
        console.error('加载 Dashboard 数据失败:', error)
      }
    }
  } catch (error) {
    console.error('加载报表数据失败:', error)
  } finally {
    loading.value = false
  }
}

let refreshInterval: number | null = null

onMounted(() => {
  refreshData()
  loadTopLists()
  // 每5分钟自动刷新一次
  refreshInterval = window.setInterval(() => {
    refreshData()
    loadTopLists()
  }, 5 * 60 * 1000)
})

onUnmounted(() => {
  if (refreshInterval !== null) {
    clearInterval(refreshInterval)
  }
})
</script>

<style scoped>
.reports-page {
  width: 100%;
  padding: 0;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 16px 20px;
  background: var(--mxsec-card-bg);
  border-radius: 12px;
  border: 1px solid var(--mxsec-border);
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}

.page-header h2 {
  margin: 0;
  font-size: 22px;
  font-weight: 700;
  background: linear-gradient(135deg, #2563eb 0%, #722ed1 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: -0.3px;
}

.header-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}

.reports-tabs {
  margin-bottom: 20px;
  background: var(--mxsec-card-bg);
  padding: 4px 16px 0 16px;
  border-radius: 12px;
  border: 1px solid var(--mxsec-border);
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);

  :deep(.ant-tabs-nav) {
    margin-bottom: 0 !important;
  }

  :deep(.ant-tabs-tab) {
    font-size: 14px !important;
    padding: 12px 8px !important;
    transition: all 0.2s ease;

    &:hover {
      color: #2563eb !important;
    }
  }

  :deep(.ant-tabs-tab-active .ant-tabs-tab-btn) {
    color: #2563eb !important;
    font-weight: 600 !important;
  }

  :deep(.ant-tabs-ink-bar) {
    background: linear-gradient(90deg, #2563eb 0%, #722ed1 100%) !important;
    height: 3px !important;
    border-radius: 3px 3px 0 0 !important;
  }
}

.stats-overview {
  margin-bottom: 16px;
}

.stat-card {
  text-align: left;
}

.stat-card-inner {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-icon-bg {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  color: var(--mxsec-card-bg);
  flex-shrink: 0;
}

.stat-hosts .stat-icon-bg {
  background: linear-gradient(135deg, #3B82F6, #2563EB);
}

.stat-baseline .stat-icon-bg {
  background: linear-gradient(135deg, #22C55E, #009A29);
}

.stat-policy .stat-icon-bg {
  background: linear-gradient(135deg, #722ed1, #531dab);
}

.stat-task .stat-icon-bg {
  background: linear-gradient(135deg, #D25F00, #d46b08);
}

.charts-row {
  margin-bottom: 16px;
}

.chart-card {
  height: 100%;
}

.chart-card :deep(.ant-card-body) {
  padding: 20px;
}

.list-card {
  height: 100%;
}

.list-card :deep(.ant-card-body) {
  padding: 12px;
}

.list-card :deep(.ant-table-wrapper) {
  margin: 0;
}

/* 响应式调整 */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 12px;
  }

  .header-actions {
    width: 100%;
    flex-direction: column;
  }

  .header-actions .ant-picker {
    width: 100%;
  }
}
</style>
