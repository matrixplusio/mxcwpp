<template>
  <div class="category-report report-print-ready">
    <div class="export-bar no-print">
      <a-button type="primary" :loading="exporting" @click="exportPDF">
        <template #icon><FilePdfOutlined /></template>
        导出 PDF
      </a-button>
      <span class="export-bar__hint">服务端 Chromium 渲染 · 矢量可搜索</span>
    </div>
    <a-spin :spinning="loading">
      <!-- 统计卡片 -->
      <a-row :gutter="[16, 16]" class="stats-overview">
        <a-col :xs="12" :sm="8" :md="8" :lg="{ span: 4, offset: 2 }">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="告警总数"
              :value="report.summary.totalAlarms"
              :value-style="{ color: '#3B82F6' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="待处理"
              :value="report.summary.pendingAlarms"
              :value-style="{ color: '#EF4444' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="已处理"
              :value="report.summary.processedAlarms"
              :value-style="{ color: '#22C55E' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="已忽略"
              :value="report.summary.ignoredAlarms"
              :value-style="{ color: '#86909C' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="集群数"
              :value="report.summary.clusterCount"
              :value-style="{ color: '#722ed1' }"
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- CIS 基线概览 -->
      <a-row :gutter="[16, 16]" class="stats-overview">
        <a-col :xs="12" :sm="8" :md="8" :lg="{ span: 4, offset: 2 }">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="基线检查项"
              :value="report.baselineOverview.totalChecks"
              :value-style="{ color: '#3B82F6' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="通过"
              :value="report.baselineOverview.passed"
              :value-style="{ color: '#22C55E' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="不合规"
              :value="report.baselineOverview.failed"
              :value-style="{ color: '#EF4444' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="通过率"
              :value="report.baselineOverview.passRate"
              :precision="1"
              suffix="%"
              :value-style="{ color: report.baselineOverview.passRate >= 80 ? '#22C55E' : report.baselineOverview.passRate >= 60 ? '#F59E0B' : '#EF4444' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="活跃告警"
              :value="report.baselineAlerts.active"
              :value-style="{ color: report.baselineAlerts.active > 0 ? '#EF4444' : '#22C55E' }"
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- 基线图表：不合规严重级别 + 不合规分类 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :xs="24" :md="12">
          <a-card title="不合规项严重级别分布" :bordered="false" class="chart-card">
            <v-chart theme="mxsec"
              v-if="hasBaselineSeverityData"
              :option="baselineSeverityChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
        <a-col :xs="24" :md="12">
          <a-card title="不合规项分类分布" :bordered="false" class="chart-card">
            <v-chart theme="mxsec"
              v-if="hasBaselineCategoryData"
              :option="baselineCategoryChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
      </a-row>

      <!-- 运行时告警图表 -->
      <a-row :gutter="[16, 16]" class="charts-row" v-if="hasSeverityData || hasAlarmTypeData">
        <a-col :xs="24" :md="12">
          <a-card title="运行时告警严重级别" :bordered="false" class="chart-card">
            <v-chart theme="mxsec"
              v-if="hasSeverityData"
              :option="severityChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
        <a-col :xs="24" :md="12">
          <a-card title="运行时告警类型" :bordered="false" class="chart-card">
            <v-chart theme="mxsec"
              v-if="hasAlarmTypeData"
              :option="alarmTypeChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
      </a-row>

      <!-- 集群分布 -->
      <a-row :gutter="[16, 16]" class="charts-row" v-if="report.clusterDistribution.length > 0">
        <a-col :span="24">
          <a-card title="集群告警分布" :bordered="false" class="chart-card">
            <v-chart theme="mxsec"
              :option="clusterChartOption"
              style="height: 320px"
              autoresize
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- Top 列表 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :xs="24" :md="12">
          <a-card title="Top 10 Namespace" :bordered="false" class="list-card">
            <a-table
              v-if="report.topNamespaces.length > 0"
              :columns="namespaceColumns"
              :data-source="report.topNamespaces"
              :pagination="false"
              :row-key="(r: { namespace: string; clusterName: string }) => `${r.clusterName}-${r.namespace}`"
              size="small"
            />
            <a-empty v-else description="暂无数据" />
          </a-card>
        </a-col>
        <a-col :xs="24" :md="12">
          <a-card title="Top 10 影响目标" :bordered="false" class="list-card">
            <a-table
              v-if="report.topTargets.length > 0"
              :columns="targetColumns"
              :data-source="report.topTargets"
              :pagination="false"
              row-key="target"
              size="small"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'severity'">
                  <a-tag :color="severityColor(record.severity)">
                    {{ severityLabel(record.severity) }}
                  </a-tag>
                </template>
              </template>
            </a-table>
            <a-empty v-else description="暂无数据" />
          </a-card>
        </a-col>
      </a-row>
    </a-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import type { Dayjs } from 'dayjs'
import type { EChartsOption } from 'echarts'
import { reportsApi, type KubeReport } from '@/api/reports'
import { FilePdfOutlined } from '@ant-design/icons-vue'

interface Props {
  dateRange: [Dayjs, Dayjs]
}

const props = defineProps<Props>()

const exporting = ref(false)
const exportPDF = async () => {
  exporting.value = true
  try {
    const blob = await reportsApi.exportKubePDF({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `Kube-Report-${props.dateRange[1].format('YYYYMMDD')}.pdf`
    a.click()
    URL.revokeObjectURL(url)
    message.success('PDF 已生成')
  } catch (e: any) {
    console.error('PDF 导出失败', e)
    message.error(`PDF 导出失败: ${e?.response?.data?.message || e?.message || e}`)
  } finally {
    exporting.value = false
  }
}

const loading = ref(false)
const report = ref<KubeReport>({
  summary: {
    totalAlarms: 0,
    pendingAlarms: 0,
    processedAlarms: 0,
    ignoredAlarms: 0,
    clusterCount: 0,
  },
  severityDistribution: {},
  alarmTypeDistribution: {},
  clusterDistribution: [],
  topNamespaces: [],
  topTargets: [],
  baselineOverview: {
    totalChecks: 0,
    passed: 0,
    failed: 0,
    passRate: 0,
  },
  baselineAlerts: {
    active: 0,
    resolved: 0,
    ignored: 0,
  },
  baselineBySeverity: {},
  baselineByCategory: {},
})

const alarmTypeTextMap: Record<string, string> = {
  container_escape: '容器逃逸',
  abnormal_process: '异常进程',
  abnormal_network: '异常网络',
  file_tamper: '文件篡改',
  privilege_escalation: '权限提升',
  reverse_shell: '反弹Shell',
  crypto_mining: '挖矿行为',
}

const severityColors: Record<string, string> = {
  critical: '#EF4444',
  high: '#ff7875',
  medium: '#ffa940',
  low: '#ffc53d',
}

const severityLabelMap: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

const severityColor = (sev: string) => {
  const map: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return map[sev] || 'default'
}

const severityLabel = (sev: string) => severityLabelMap[sev] || sev

const hasSeverityData = computed(() =>
  Object.values(report.value.severityDistribution).some(v => v > 0)
)
const hasAlarmTypeData = computed(() =>
  Object.values(report.value.alarmTypeDistribution).some(v => v > 0)
)

const categoryLabelMap: Record<string, string> = {
  'RBAC': 'RBAC', 'Pod Security': 'Pod 安全', 'Network': '网络', 'Secrets & Config': '密钥配置',
  'Workload': '工作负载', 'Node': '节点', 'Cluster Config': '集群配置', 'Supply Chain': '供应链', 'Runtime': '运行时',
}

const hasBaselineSeverityData = computed(() =>
  Object.values(report.value.baselineBySeverity).some(v => v > 0)
)
const hasBaselineCategoryData = computed(() =>
  Object.values(report.value.baselineByCategory).some(v => v > 0)
)

const baselineSeverityChartOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', left: 'left' },
  series: [
    {
      name: '严重级别',
      type: 'pie',
      radius: ['40%', '70%'],
      itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
      data: (['critical', 'high', 'medium', 'low'] as const)
        .map(sev => ({
          value: report.value.baselineBySeverity[sev] || 0,
          name: severityLabelMap[sev],
          itemStyle: { color: severityColors[sev] },
        }))
        .filter(item => item.value > 0),
    },
  ],
}))

const baselineCategoryChartOption = computed<EChartsOption>(() => {
  const entries = Object.entries(report.value.baselineByCategory).filter(([, v]) => v > 0)
  const labels = entries.map(([k]) => categoryLabelMap[k] || k)
  const values = entries.map(([, v]) => v)
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: labels, axisLabel: { rotate: 30, interval: 0 } },
    yAxis: { type: 'value' },
    series: [{ name: '不合规数', type: 'bar', data: values, itemStyle: { color: '#EF4444' } }],
  }
})

const severityChartOption = computed<EChartsOption>(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { orient: 'vertical', left: 'left' },
  series: [
    {
      name: '严重级别',
      type: 'pie',
      radius: ['40%', '70%'],
      itemStyle: { borderRadius: 8, borderColor: '#fff', borderWidth: 2 },
      data: (['critical', 'high', 'medium', 'low'] as const)
        .map(sev => ({
          value: report.value.severityDistribution[sev] || 0,
          name: severityLabelMap[sev],
          itemStyle: { color: severityColors[sev] },
        }))
        .filter(item => item.value > 0),
    },
  ],
}))

const alarmTypeChartOption = computed<EChartsOption>(() => {
  const entries = Object.entries(report.value.alarmTypeDistribution).filter(([, v]) => v > 0)
  const labels = entries.map(([k]) => alarmTypeTextMap[k] || k)
  const values = entries.map(([, v]) => v)
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: labels,
      axisLabel: { rotate: 30, interval: 0 },
    },
    yAxis: { type: 'value' },
    series: [
      {
        name: '数量',
        type: 'bar',
        data: values,
        itemStyle: { color: '#F59E0B' },
      },
    ],
  }
})

const clusterChartOption = computed<EChartsOption>(() => {
  const data = report.value.clusterDistribution
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map(item => item.clusterName),
      axisLabel: { interval: 0, rotate: data.length > 6 ? 30 : 0 },
    },
    yAxis: { type: 'value' },
    series: [
      {
        name: '告警数',
        type: 'bar',
        data: data.map(item => item.count),
        itemStyle: { color: '#3B82F6' },
      },
    ],
  }
})

const namespaceColumns = [
  { title: '命名空间', key: 'namespace', dataIndex: 'namespace', ellipsis: true },
  { title: '集群', key: 'clusterName', dataIndex: 'clusterName', ellipsis: true, width: 120 },
  { title: '告警数', key: 'count', dataIndex: 'count', width: 80 },
]

const targetColumns = [
  { title: '目标', key: 'target', dataIndex: 'target', ellipsis: true },
  { title: '命名空间', key: 'namespace', dataIndex: 'namespace', ellipsis: true, width: 100 },
  { title: '级别', key: 'severity', width: 80 },
  { title: '告警数', key: 'count', dataIndex: 'count', width: 80 },
]

const loadData = async () => {
  loading.value = true
  try {
    const data = await reportsApi.getKubeReport({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    report.value = data
  } catch (error) {
    console.error('加载容器安全报告失败:', error)
    message.error('加载容器安全报告失败')
  } finally {
    loading.value = false
  }
}

const refresh = () => loadData()

defineExpose({ refresh })

watch(
  () => props.dateRange,
  () => loadData(),
  { deep: true }
)

onMounted(loadData)
</script>

<style scoped>
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

.category-report {
  width: 100%;
}

.stats-overview {
  margin-bottom: 16px;
}

.stat-card {
  text-align: left;
}

.charts-row {
  margin-bottom: 16px;
}

.chart-card,
.list-card {
  height: 100%;
}

.chart-card :deep(.ant-card-body) {
  padding: 20px;
}

.list-card :deep(.ant-card-body) {
  padding: 12px;
}
</style>
