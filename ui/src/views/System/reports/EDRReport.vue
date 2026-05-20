<template>
  <div class="category-report">
    <a-spin :spinning="loading">
      <!-- 统计卡片 -->
      <a-row :gutter="[16, 16]" class="stats-overview">
        <a-col :xs="12" :sm="8" :md="8" :lg="{ span: 4, offset: 2 }">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="总告警"
              :value="report.summary.totalAlerts"
              :value-style="{ color: '#165DFF' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="活跃"
              :value="report.summary.activeAlerts"
              :value-style="{ color: '#F53F3F' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="已解决"
              :value="report.summary.resolvedAlerts"
              :value-style="{ color: '#00B42A' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="今日新增"
              :value="report.summary.todayAlerts"
              :value-style="{ color: '#FF7D00' }"
            />
          </a-card>
        </a-col>
        <a-col :xs="12" :sm="8" :md="8" :lg="4">
          <a-card :bordered="false" class="stat-card">
            <a-statistic
              title="影响主机"
              :value="report.summary.affectedHosts"
              :value-style="{ color: '#722ed1' }"
            />
          </a-card>
        </a-col>
      </a-row>

      <!-- 图表行 1：严重级别 + 规则分类 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :xs="24" :md="12">
          <a-card title="严重级别分布" :bordered="false" class="chart-card">
            <v-chart
              v-if="hasSeverityData"
              :option="severityChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
        <a-col :xs="24" :md="12">
          <a-card title="规则分类分布" :bordered="false" class="chart-card">
            <v-chart
              v-if="report.categoryDistribution.length > 0"
              :option="categoryChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
      </a-row>

      <!-- 图表行 2：MITRE -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :span="24">
          <a-card title="MITRE ATT&CK 分布" :bordered="false" class="chart-card">
            <v-chart
              v-if="report.mitreDistribution.length > 0"
              :option="mitreChartOption"
              style="height: 320px"
              autoresize
            />
            <a-empty v-else description="暂无数据" style="height: 320px; display: flex; align-items: center; justify-content: center;" />
          </a-card>
        </a-col>
      </a-row>

      <!-- Top 列表 -->
      <a-row :gutter="[16, 16]" class="charts-row">
        <a-col :xs="24" :md="12">
          <a-card title="Top 10 检测规则" :bordered="false" class="list-card">
            <a-table
              v-if="report.topRules.length > 0"
              :columns="ruleColumns"
              :data-source="report.topRules"
              :pagination="false"
              row-key="ruleId"
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
                <template v-else-if="column.key === 'alertCount'">
                  <span style="color: #F53F3F; font-weight: 500;">{{ record.alertCount }}</span>
                </template>
                <template v-else-if="column.key === 'criticalCount'">
                  <a-tag v-if="record.criticalCount > 0" color="red">
                    严重 {{ record.criticalCount }}
                  </a-tag>
                  <span v-else style="color: #86909C;">-</span>
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
import { reportsApi, type EDRReport } from '@/api/reports'

interface Props {
  dateRange: [Dayjs, Dayjs]
}

const props = defineProps<Props>()

const loading = ref(false)
const report = ref<EDRReport>({
  summary: {
    totalAlerts: 0,
    activeAlerts: 0,
    resolvedAlerts: 0,
    todayAlerts: 0,
    affectedHosts: 0,
  },
  severityDistribution: {},
  categoryDistribution: [],
  mitreDistribution: [],
  topRules: [],
  topAffectedHosts: [],
})

const severityColors: Record<string, string> = {
  critical: '#F53F3F',
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

const categoryChartOption = computed<EChartsOption>(() => {
  const data = report.value.categoryDistribution
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: data.map(item => item.category),
      axisLabel: { rotate: 30, interval: 0 },
    },
    yAxis: { type: 'value' },
    series: [
      {
        name: '数量',
        type: 'bar',
        data: data.map(item => item.count),
        itemStyle: { color: '#722ed1' },
      },
    ],
  }
})

const mitreChartOption = computed<EChartsOption>(() => {
  const data = report.value.mitreDistribution
  return {
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'value' },
    yAxis: {
      type: 'category',
      data: data.map(item => item.mitreId).reverse(),
      axisLabel: { interval: 0 },
    },
    series: [
      {
        name: '数量',
        type: 'bar',
        data: data.map(item => item.count).reverse(),
        itemStyle: { color: '#165DFF' },
      },
    ],
  }
})

const ruleColumns = [
  { title: '规则名称', key: 'ruleName', dataIndex: 'ruleName', ellipsis: true },
  { title: '级别', key: 'severity', width: 80 },
  { title: '命中数', key: 'count', dataIndex: 'count', width: 80 },
]

const hostColumns = [
  { title: '主机', key: 'hostname', ellipsis: true },
  { title: '告警数', key: 'alertCount', width: 90 },
  { title: '严重', key: 'criticalCount', width: 100 },
]

const loadData = async () => {
  loading.value = true
  try {
    const data = await reportsApi.getEDRReport({
      start_time: props.dateRange[0].format('YYYY-MM-DD'),
      end_time: props.dateRange[1].format('YYYY-MM-DD'),
    })
    report.value = data
  } catch (error) {
    console.error('加载 EDR 报告失败:', error)
    message.error('加载 EDR 报告失败')
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
