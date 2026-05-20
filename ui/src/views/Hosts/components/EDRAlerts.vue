<template>
  <div class="host-edr-alerts">
    <a-row :gutter="[16, 16]" style="margin-bottom: 16px">
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ stats.active }}</div>
          <div class="stat-label">活跃告警</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value critical">{{ stats.critical }}</div>
          <div class="stat-label">紧急</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value high">{{ stats.high }}</div>
          <div class="stat-label">高危</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="6">
        <div class="stat-card">
          <div class="stat-value">{{ stats.resolved }}</div>
          <div class="stat-label">已解决</div>
        </div>
      </a-col>
    </a-row>

    <a-card title="EDR 告警" :bordered="false">
      <div class="filter-bar">
        <a-input-search
          v-model:value="keyword"
          placeholder="搜索告警标题或描述"
          style="width: 260px"
          allow-clear
          @search="handleFilterChange"
        />
        <a-select
          v-model:value="filterSeverity"
          style="width: 120px"
          placeholder="严重级别"
          allow-clear
          @change="handleFilterChange"
        >
          <a-select-option value="critical">紧急</a-select-option>
          <a-select-option value="high">高危</a-select-option>
          <a-select-option value="medium">中危</a-select-option>
          <a-select-option value="low">低危</a-select-option>
        </a-select>
        <a-select
          v-model:value="filterRuntimeType"
          style="width: 140px"
          placeholder="事件类型"
          allow-clear
          @change="handleFilterChange"
        >
          <a-select-option value="process">进程事件</a-select-option>
          <a-select-option value="file">文件事件</a-select-option>
          <a-select-option value="network">网络事件</a-select-option>
        </a-select>
        <a-select
          v-model:value="filterStatus"
          style="width: 120px"
          placeholder="状态"
          allow-clear
          @change="handleFilterChange"
        >
          <a-select-option value="active">活跃</a-select-option>
          <a-select-option value="resolved">已解决</a-select-option>
          <a-select-option value="ignored">已忽略</a-select-option>
        </a-select>
        <a-button @click="handleReset">重置</a-button>
      </div>

      <a-table
        :columns="columns"
        :data-source="alerts"
        :loading="loading"
        :pagination="pagination"
        size="middle"
        row-key="id"
        @change="handleTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'severity'">
            <a-tag :color="severityColorMap[record.severity]" :bordered="false">
              {{ severityTextMap[record.severity] }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'status'">
            <a-tag :color="statusColorMap[record.status]" :bordered="false">
              {{ statusTextMap[record.status] }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-space>
              <router-link :to="`/alerts/${record.id}`">
                <a-button type="link" size="small">详情</a-button>
              </router-link>
              <a-button
                v-if="record.status === 'active'"
                type="link"
                size="small"
                @click="handleResolve(record)"
              >
                解决
              </a-button>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { alertsApi } from '@/api/alerts'
import type { Alert } from '@/api/alerts'

const props = defineProps<{
  hostId: string
}>()

const keyword = ref('')
const filterSeverity = ref<string>()
const filterStatus = ref<string>()
const filterRuntimeType = ref<string>()
const loading = ref(false)
const alerts = ref<Alert[]>([])
const stats = ref({ active: 0, resolved: 0, critical: 0, high: 0 })

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

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

const statusColorMap: Record<string, string> = {
  active: 'red',
  resolved: 'green',
  ignored: 'default',
}

const statusTextMap: Record<string, string> = {
  active: '活跃',
  resolved: '已解决',
  ignored: '已忽略',
}

const columns = [
  { title: '告警标题', dataIndex: 'title', key: 'title', ellipsis: true },
  { title: '严重级别', key: 'severity', width: 100 },
  { title: '分类', dataIndex: 'category', key: 'category', width: 120 },
  { title: '状态', key: 'status', width: 100 },
  { title: '首次发现', dataIndex: 'first_seen_at', key: 'first_seen_at', width: 170 },
  { title: '操作', key: 'action', width: 140 },
]

const loadAlerts = async () => {
  if (!props.hostId) return
  loading.value = true
  try {
    const res = await alertsApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      host_id: props.hostId,
      alert_type: 'detection_rule' as any,
      keyword: keyword.value || undefined,
      severity: (filterSeverity.value || undefined) as 'critical' | 'high' | 'medium' | 'low' | undefined,
      status: filterStatus.value as any || undefined,
      runtime_type: filterRuntimeType.value || undefined,
    })
    alerts.value = res.items ?? []
    pagination.value.total = res.total ?? 0

    const all = alerts.value
    stats.value = {
      active: res.total ?? 0,
      resolved: 0,
      critical: all.filter(a => a.severity === 'critical').length,
      high: all.filter(a => a.severity === 'high').length,
    }
  } catch {
    alerts.value = []
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadAlerts()
}

const handleFilterChange = () => {
  pagination.value.current = 1
  loadAlerts()
}

const handleReset = () => {
  keyword.value = ''
  filterSeverity.value = undefined
  filterStatus.value = undefined
  filterRuntimeType.value = undefined
  pagination.value.current = 1
  loadAlerts()
}

const handleResolve = async (record: Alert) => {
  try {
    await alertsApi.resolve(record.id)
    message.success('已标记为解决')
    loadAlerts()
  } catch {
    message.error('操作失败')
  }
}

onMounted(() => {
  loadAlerts()
})

watch(
  () => props.hostId,
  () => {
    pagination.value.current = 1
    loadAlerts()
  }
)
</script>

<style scoped>
.host-edr-alerts {
  width: 100%;
}

.stat-card {
  padding: 18px;
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  text-align: center;
}

.stat-value {
  font-size: 24px;
  font-weight: 700;
  color: #1D2129;
}

.stat-value.critical { color: #F53F3F; }
.stat-value.high { color: #FF7D00; }

.stat-label {
  margin-top: 8px;
  font-size: 12px;
  color: #86909C;
}

.filter-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}
</style>
