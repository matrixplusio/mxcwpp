<template>
  <div class="category-report">
    <a-spin :spinning="loading">
      <!-- 统计卡片 -->
      <a-row :gutter="[16, 16]" class="stats-overview">
        <a-col :xs="12" :sm="8" :md="8" :lg="{ span: 4, offset: 2 }">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="扫描任务"
              :value="report.summary.totalTasks"
              :value-style="{ color: '#3B82F6' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="威胁总数"
              :value="report.summary.totalThreats"
              :value-style="{ color: '#722ed1' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="待处理"
              :value="report.summary.detectedThreats"
              :value-style="{ color: '#EF4444' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="已隔离"
              :value="report.summary.quarantinedThreats"
              :value-style="{ color: '#F59E0B' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="影响主机"
              :value="report.summary.affectedHosts"
              :value-style="{ color: '#22C55E' }"
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- 图表行 1：严重级别 + 威胁类型 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :xs="24" :md="12">
          <a-card title="威胁严重级别分布" :bordered="false" class="chart-card">
            <v-chart
              v-if="hasSeverityData"
              :option="severityChartOption"
              style="height: 300px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 300px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
        <a-col :xs="24" :md="12">
          <a-card title="威胁类型分布" :bordered="false" class="chart-card">
            <v-chart
              v-if="hasThreatTypeData"
              :option="threatTypeChartOption"
              style="height: 300px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 300px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
      </a-row>

      <!-- 图表行 2：处置动作 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :span="24">
          <a-card title="处置动作分布" :bordered="false" class="chart-card">
            <v-chart
              v-if="hasActionData"
              :option="actionChartOption"
              style="height: 300px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 300px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
      </a-row>

      <!-- Top 列表 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :xs="24" :md="12">
          <a-card title="Top 10 威胁名称" :bordered="false" class="list-card">
            <a-table
              v-if="report.topThreats.length > 0"
              :columns="threatColumns"
              :data-source="report.topThreats"
              :pagination="false"
              row-key="threatName"
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
            <a-empty v-else description="暂无威胁记录" />
          </a-card>
        </a-col>
        <a-col :xs="24" :md="12">
          <a-card title="Top 10 受影响主机" :bordered="false" class="list-card">
            <a-table
              v-if="report.topAffectedHosts.length > 0"
              :columns="hostColumns"
              :data-source="report.topAffectedHosts"
              :pagination="false"
              row-key="hostId"
              size="small"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'hostname'">
                  <span>{{ record.hostname || record.hostId.slice(0, 8) }}</span>
                  <span v-if="record.ip" style="color: #86909C; margin-left: 4px; font-size: 12px;">
                    ({{ record.ip }})
                  </span>
                </template>
                <template v-else-if="column.key === 'threatCount'">
                  <span style="color: #EF4444; font-weight: 500;">{{ record.threatCount }}</span>
                </template>
              </template>
            </a-table>
            <a-empty v-else description="暂无受影响主机" />
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
import { reportsApi, type AntivirusReport } from '@/api/reports'

interface Props {
  dateRange: [Dayjs, Dayjs]
}

const props = defineProps<Props>()

const loading = ref(false)
const report = ref<AntivirusReport>({
  summary: {
    totalTasks: 0,
    totalThreats: 0,
    detectedThreats: 0,
    quarantinedThreats: 0,
    affectedHosts: 0,
  },
  severityDistribution: {},
  threatTypeDistribution: {},
  actionDistribution: {},
  topThreats: [],
  topAffectedHosts: [],
})

const threatTypeMap: Record<string, string> = {
  virus: '病毒',
  trojan: '木马',
  worm: '蠕虫',
  ransomware: '勒索',
  rootkit: 'Rootkit',
  miner: '挖矿',
  backdoor: '后门',
  other: '其他',
}

const actionMap: Record<string, string> = {
  detected: '已检测',
  quarantined: '已隔离',
  deleted: '已删除',
  ignored: '已忽略',
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
const hasThreatTypeData = computed(() =>
  Object.values(report.value.threatTypeDistribution).some(v => v > 0)
)
const hasActionData = computed(() =>
  Object.values(report.value.actionDistribution).some(v => v > 0)
)

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

const threatTypeChartOption = computed<EChartsOption>(() => {
  const data = Object.entries(report.value.threatTypeDistribution)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({
      name: threatTypeMap[name] || name,
      value,
    }))
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { orient: 'vertical', left: 'left' },
    series: [
      {
        name: '威胁类型',
        type: 'pie',
        radius: '60%',
        data,
      },
    ],
  }
})

const actionChartOption = computed<EChartsOption>(() => {
  const keys = ['detected', 'quarantined', 'deleted', 'ignored']
  const labels = keys.map(k => actionMap[k])
  const values = keys.map(k => report.value.actionDistribution[k] || 0)
  const colors = ['#EF4444', '#F59E0B', '#3B82F6', '#86909C']
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: labels },
    yAxis: { type: 'value' },
    series: [
      {
        name: '数量',
        type: 'bar',
        data: values.map((v, i) => ({ value: v, itemStyle: { color: colors[i] } })),
      },
    ],
  }
})

const threatColumns = [
  { title: '威胁名称', key: 'threatName', dataIndex: 'threatName', ellipsis: true },
  { title: '级别', key: 'severity', width: 80 },
  { title: '数量', key: 'count', dataIndex: 'count', width: 80 },
  { title: '影响主机', key: 'affectedHosts', dataIndex: 'affectedHosts', width: 90 },
]

const hostColumns = [
  { title: '主机', key: 'hostname', ellipsis: true },
  { title: '威胁数', key: 'threatCount', width: 100 },
]

const loadData = async () => {
  loading.value = true
  try {
    const data = await reportsApi.getAntivirusReport({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    report.value = data
  } catch (error) {
    console.error('加载病毒查杀报告失败:', error)
    message.error('加载病毒查杀报告失败')
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
