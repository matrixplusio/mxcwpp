<template>
  <div class="bde-page">
    <div class="page-header">
      <h2>行为基线引擎</h2>
      <a-button @click="handleRefresh">
        <ReloadOutlined /> 刷新
      </a-button>
    </div>

    <!-- 统计卡片 (统一 StatCard) -->
    <a-row :gutter="16" class="stat-cards">
      <a-col :span="6"><StatCard title="总主机" :value="stats.total_hosts" color="#86909C" /></a-col>
      <a-col :span="6"><StatCard title="学习中" :value="stats.learning_hosts" color="#3B82F6" /></a-col>
      <a-col :span="6"><StatCard title="检测中" :value="stats.active_hosts" color="#22C55E" /></a-col>
      <a-col :span="6"><StatCard title="待处理告警" :value="stats.open_alerts" color="#EF4444" /></a-col>
    </a-row>

    <!-- Tab 切换 -->
    <a-tabs v-model:activeKey="activeTab">
      <a-tab-pane key="states" tab="基线状态">
        <div class="filter-bar">
          <a-input
            v-model:value="stateFilters.host_id"
            placeholder="主机 ID"
            style="width: 200px"
            allow-clear
            @pressEnter="fetchStates"
          />
          <a-select
            v-model:value="stateFilters.phase"
            placeholder="阶段"
            style="width: 120px"
            allow-clear
            @change="fetchStates"
          >
            <a-select-option value="learning">学习中</a-select-option>
            <a-select-option value="active">检测中</a-select-option>
          </a-select>
        </div>

        <a-table
          :columns="stateColumns"
          :data-source="states"
          :loading="statesLoading"
          :pagination="statePagination"
          row-key="id"
          size="small"
          @change="handleStateTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'phase'">
              <a-tag :color="record.phase === 'learning' ? 'blue' : 'green'">
                {{ record.phase === 'learning' ? '学习中' : '检测中' }}
              </a-tag>
            </template>
            <template v-if="column.key === 'progress'">
              <a-progress
                v-if="record.phase === 'learning'"
                :percent="Math.min(Math.round(record.samples / 10), 100)"
                :size="[100, 6]"
                :show-info="true"
              />
              <a-tag v-else color="green">已完成</a-tag>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <a-tab-pane key="alerts" tab="行为告警">
        <div class="filter-bar">
          <a-input
            v-model:value="alertFilters.host_id"
            placeholder="主机 ID"
            style="width: 200px"
            allow-clear
            @pressEnter="fetchAlerts"
          />
          <a-select
            v-model:value="alertFilters.status"
            placeholder="状态"
            style="width: 120px"
            allow-clear
            @change="fetchAlerts"
          >
            <a-select-option value="open">待处理</a-select-option>
            <a-select-option value="resolved">已处理</a-select-option>
            <a-select-option value="ignored">已忽略</a-select-option>
          </a-select>
          <a-select
            v-model:value="alertFilters.metric"
            placeholder="指标"
            style="width: 160px"
            allow-clear
            @change="fetchAlerts"
          >
            <a-select-option v-for="m in metricOptions" :key="m.value" :value="m.value">
              {{ m.label }}
            </a-select-option>
          </a-select>
        </div>

        <a-table
          :columns="alertColumns"
          :data-source="alerts"
          :loading="alertsLoading"
          :pagination="alertPagination"
          row-key="id"
          size="small"
          @change="handleAlertTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'risk_score'">
              <a-progress
                :percent="record.risk_score"
                :stroke-color="record.risk_score >= 80 ? '#EF4444' : record.risk_score >= 60 ? '#F59E0B' : '#F7BA1E'"
                :size="[80, 6]"
                :show-info="true"
              />
            </template>
            <template v-if="column.key === 'metric'">
              <span class="mono-text">{{ record.metric }}</span>
            </template>
            <template v-if="column.key === 'deviation'">
              <span>值: {{ record.value.toFixed(2) }}</span>
              <span class="detail-secondary"> / 均值: {{ record.mean.toFixed(2) }}</span>
              <span class="z-score"> (z={{ record.z_score.toFixed(1) }})</span>
            </template>
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'open' ? 'orange' : record.status === 'resolved' ? 'green' : 'default'">
                {{ { open: '待处理', resolved: '已处理', ignored: '已忽略' }[record.status as string] }}
              </a-tag>
            </template>
          </template>
        </a-table>
      </a-tab-pane>
    </a-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import { bdeApi } from '@/api/bde'
import type { HostBaselineState, BehaviorAlert, BaselineStats } from '@/api/bde'
import StatCard from '@/components/StatCard.vue'

const activeTab = ref('states')
const statesLoading = ref(false)
const alertsLoading = ref(false)
const states = ref<HostBaselineState[]>([])
const alerts = ref<BehaviorAlert[]>([])
const stats = reactive<BaselineStats>({ total_hosts: 0, learning_hosts: 0, active_hosts: 0, open_alerts: 0 })

const stateFilters = reactive({
  host_id: '',
  phase: undefined as string | undefined,
})

const alertFilters = reactive({
  host_id: '',
  status: undefined as string | undefined,
  metric: undefined as string | undefined,
})

const statePagination = reactive({
  current: 1, pageSize: 20, total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const alertPagination = reactive({
  current: 1, pageSize: 20, total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const metricOptions = [
  { value: 'proc_exec_count', label: '进程执行数' },
  { value: 'proc_unique_exe', label: '唯一可执行文件' },
  { value: 'proc_fork_rate', label: '进程 Fork 速率' },
  { value: 'file_write_count', label: '文件写入数' },
  { value: 'file_unique_path', label: '唯一文件路径' },
  { value: 'file_sensitive_hits', label: '敏感文件命中' },
  { value: 'net_connect_count', label: '网络连接数' },
  { value: 'net_unique_ip', label: '唯一 IP' },
  { value: 'net_unique_port', label: '唯一端口' },
  { value: 'net_external_ratio', label: '外部连接比例' },
  { value: 'dns_query_count', label: 'DNS 查询数' },
  { value: 'dns_unique_domain', label: '唯一域名' },
  { value: 'dns_nx_ratio', label: 'DNS NX 比例' },
]

const stateColumns = [
  { title: '主机 ID', dataIndex: 'host_id', width: 280, ellipsis: true },
  { title: '阶段', key: 'phase', width: 100, align: 'center' as const },
  { title: '样本数', dataIndex: 'samples', width: 100, align: 'center' as const },
  { title: '学习进度', key: 'progress', width: 150 },
  { title: '首次采集', dataIndex: 'first_seen', width: 170 },
  { title: '更新时间', dataIndex: 'updated_at', width: 170 },
]

const alertColumns = [
  { title: '时间', dataIndex: 'created_at', width: 170 },
  { title: '主机', dataIndex: 'hostname', width: 120, ellipsis: true },
  { title: '风险分', key: 'risk_score', width: 120 },
  { title: '指标', key: 'metric', width: 150 },
  { title: '偏差详情', key: 'deviation', width: 280 },
  { title: '状态', key: 'status', width: 80, align: 'center' as const },
]

const fetchStates = async () => {
  statesLoading.value = true
  try {
    const res = await bdeApi.listBaselineStates({
      page: statePagination.current,
      page_size: statePagination.pageSize,
      host_id: stateFilters.host_id || undefined,
      phase: stateFilters.phase,
    })
    states.value = res.items || []
    statePagination.total = res.total
  } catch {
    // handled
  } finally {
    statesLoading.value = false
  }
}

const fetchAlerts = async () => {
  alertsLoading.value = true
  try {
    const res = await bdeApi.listAlerts({
      page: alertPagination.current,
      page_size: alertPagination.pageSize,
      host_id: alertFilters.host_id || undefined,
      status: alertFilters.status,
      metric: alertFilters.metric,
    })
    alerts.value = res.items || []
    alertPagination.total = res.total
  } catch {
    // handled
  } finally {
    alertsLoading.value = false
  }
}

const fetchStats = async () => {
  try {
    const res = await bdeApi.baselineStats()
    Object.assign(stats, res)
  } catch {
    // silent
  }
}

const handleRefresh = () => {
  fetchStats()
  fetchStates()
  fetchAlerts()
}

const handleStateTableChange = (pag: any) => {
  statePagination.current = pag.current
  statePagination.pageSize = pag.pageSize
  fetchStates()
}

const handleAlertTableChange = (pag: any) => {
  alertPagination.current = pag.current
  alertPagination.pageSize = pag.pageSize
  fetchAlerts()
}

onMounted(() => {
  fetchStats()
  fetchStates()
  fetchAlerts()
})
</script>

<style scoped>
.bde-page { padding: 0; }
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.page-header h2 { margin: 0; font-size: 20px; }
.stat-cards { margin-bottom: 16px; }
.filter-bar {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.mono-text { font-family: monospace; font-size: 13px; }
.detail-secondary { color: #999; }
.z-score { color: #EF4444; font-size: 12px; }
</style>
