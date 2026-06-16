<template>
  <div class="fim-dashboard">
    <div class="page-header">
      <h2>FIM 概览</h2>
      <a-space>
        <a-radio-group v-model:value="days" size="small" @change="fetchStats">
          <a-radio-button :value="7">近 7 天</a-radio-button>
          <a-radio-button :value="30">近 30 天</a-radio-button>
        </a-radio-group>
        <a-button @click="fetchStats">
          <ReloadOutlined /> 刷新
        </a-button>
      </a-space>
    </div>

    <!-- 统计卡片 (统一 StatCard) -->
    <a-row :gutter="16" class="stat-cards">
      <a-col :span="4"><StatCard title="总变更事件" :value="stats.total" color="#3B82F6" /></a-col>
      <a-col :span="4"><StatCard title="待确认事件" :value="stats.pending" color="#F59E0B" /></a-col>
      <a-col :span="4"><StatCard title="待审批基线" :value="pendingBaselines" color="#722ED1" /></a-col>
      <a-col :span="4"><StatCard title="严重/高危" :value="stats.critical + stats.high" color="#DC2626" /></a-col>
      <a-col :span="4"><StatCard title="新增文件" :value="stats.added" color="#22C55E" /></a-col>
      <a-col :span="4"><StatCard title="删除文件" :value="stats.removed" color="#EF4444" /></a-col>
    </a-row>

    <!-- 图表区 -->
    <a-row :gutter="16" style="margin-top: 16px">
      <!-- 变更趋势折线图 -->
      <a-col :span="16">
        <a-card title="变更趋势" size="small">
          <v-chart :option="trendChartOption" style="height: 300px" autoresize />
        </a-card>
      </a-col>

      <!-- 严重等级分布饼图 -->
      <a-col :span="8">
        <a-card title="严重等级分布" size="small">
          <v-chart :option="severityPieOption" style="height: 300px" autoresize />
        </a-card>
      </a-col>
    </a-row>

    <a-row :gutter="16" style="margin-top: 16px">
      <!-- 分类分布饼图 -->
      <a-col :span="8">
        <a-card title="文件分类分布" size="small">
          <v-chart :option="categoryPieOption" style="height: 300px" autoresize />
        </a-card>
      </a-col>

      <!-- Top 10 变更主机 -->
      <a-col :span="16">
        <a-card title="Top 10 变更主机" size="small">
          <a-table
            :columns="topHostColumns"
            :data-source="stats.top_hosts"
            :pagination="false"
            size="small"
            row-key="host_id"
          >
            <template #bodyCell="{ column, record, index }">
              <template v-if="column.key === 'rank'">
                <a-tag :color="index < 3 ? 'red' : 'default'">{{ index + 1 }}</a-tag>
              </template>
              <template v-if="column.key === 'count'">
                <span style="font-weight: 600; color: #fa541c">{{ record.count }}</span>
              </template>
            </template>
          </a-table>
        </a-card>
      </a-col>
    </a-row>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import {
  ReloadOutlined,
} from '@ant-design/icons-vue'
import { fimApi } from '@/api/fim'
import type { FIMEventStats } from '@/api/types'
import StatCard from '@/components/StatCard.vue'

const days = ref(7)

const pendingBaselines = ref(0)

const stats = reactive<FIMEventStats>({
  total: 0,
  pending: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  added: 0,
  removed: 0,
  changed: 0,
  by_category: {},
  top_hosts: [],
  trend: [],
})

const topHostColumns = [
  { title: '#', key: 'rank', width: 50 },
  { title: '主机名', dataIndex: 'hostname' },
  { title: '事件数', key: 'count', width: 100, align: 'center' as const },
]

const trendChartOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  grid: { left: 40, right: 20, top: 20, bottom: 30 },
  xAxis: {
    type: 'category',
    data: stats.trend.map((t) => t.date),
    axisLabel: { fontSize: 11 },
  },
  yAxis: {
    type: 'value',
    minInterval: 1,
    axisLabel: { fontSize: 11 },
  },
  series: [
    {
      name: '变更事件',
      type: 'line',
      data: stats.trend.map((t) => t.count),
      smooth: true,
      areaStyle: { opacity: 0.15 },
      lineStyle: { width: 2 },
      itemStyle: { color: '#3B82F6' },
    },
  ],
}))

const severityPieOption = computed(() => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
  legend: { bottom: 0, textStyle: { fontSize: 11 } },
  series: [
    {
      type: 'pie',
      radius: ['40%', '70%'],
      center: ['50%', '45%'],
      label: { show: false },
      data: [
        { value: stats.critical, name: '严重', itemStyle: { color: '#DC2626' } },
        { value: stats.high, name: '高危', itemStyle: { color: '#fa541c' } },
        { value: stats.medium, name: '中危', itemStyle: { color: '#F59E0B' } },
        { value: stats.low, name: '低危', itemStyle: { color: '#3B82F6' } },
      ].filter((d) => d.value > 0),
    },
  ],
}))

const categoryPieOption = computed(() => {
  const categoryLabels: Record<string, string> = {
    binary: '二进制',
    config: '配置文件',
    auth: '认证文件',
    ssh: 'SSH',
    log: '日志',
    other: '其他',
  }
  const data = Object.entries(stats.by_category).map(([key, value]) => ({
    name: categoryLabels[key] || key,
    value,
  }))
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, textStyle: { fontSize: 11 } },
    series: [
      {
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['50%', '45%'],
        label: { show: false },
        data,
      },
    ],
  }
})

const fetchStats = async () => {
  try {
    const res = await fimApi.getEventStats(days.value)
    Object.assign(stats, res)
  } catch {
    // API 客户端已处理错误提示
  }
}

const fetchPendingBaselines = async () => {
  try {
    const res = await fimApi.listBaselines({ page: 1, page_size: 1, status: 'pending' })
    pendingBaselines.value = res.total
  } catch {
    // 静默处理
  }
}

onMounted(() => {
  fetchStats()
  fetchPendingBaselines()
})
</script>

<style scoped>
.fim-dashboard {
  padding: 0;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
}

.stat-cards .ant-card {
  text-align: center;
}
</style>
