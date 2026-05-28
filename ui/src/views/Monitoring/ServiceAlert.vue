<template>
  <div class="service-alert-page">
    <div class="page-header">
      <h2>服务告警</h2>
      <span class="page-header-hint">后端服务异常告警记录</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :span="6">
        <div class="alert-stat-card">
          <div class="alert-stat-value" style="color: #EF4444">{{ stats.critical }}</div>
          <div class="alert-stat-label">紧急告警</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="alert-stat-card">
          <div class="alert-stat-value" style="color: #F59E0B">{{ stats.warning }}</div>
          <div class="alert-stat-label">警告</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="alert-stat-card">
          <div class="alert-stat-value" style="color: #3B82F6">{{ stats.info }}</div>
          <div class="alert-stat-label">通知</div>
        </div>
      </a-col>
      <a-col :span="6">
        <div class="alert-stat-card">
          <div class="alert-stat-value" style="color: #22C55E">{{ stats.resolved }}</div>
          <div class="alert-stat-label">已恢复</div>
        </div>
      </a-col>
    </a-row>

    <!-- 筛选栏 + 表格 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索告警内容"
            style="width: 240px"
            allow-clear
            @search="loadAlerts"
          />
          <a-select v-model:value="filterSeverity" style="width: 140px" placeholder="告警级别" allow-clear @change="loadAlerts">
            <a-select-option value="critical">紧急</a-select-option>
            <a-select-option value="warning">警告</a-select-option>
            <a-select-option value="info">通知</a-select-option>
          </a-select>
          <a-select v-model:value="filterService" style="width: 140px" placeholder="服务" allow-clear @change="loadAlerts">
            <a-select-option value="manager">Manager</a-select-option>
            <a-select-option value="agentcenter">AgentCenter</a-select-option>
            <a-select-option value="mysql">MySQL</a-select-option>
          </a-select>
          <a-select v-model:value="filterStatus" style="width: 140px" placeholder="状态" allow-clear @change="loadAlerts">
            <a-select-option value="firing">告警中</a-select-option>
            <a-select-option value="resolved">已恢复</a-select-option>
          </a-select>
          <a-range-picker v-model:value="dateRange" style="width: 240px" @change="loadAlerts" />
        </div>

        <a-table
          :columns="columns"
          :data-source="alerts"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="middle"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'severity'">
              <a-tag :color="severityColorMap[record.severity]" :bordered="false">
                {{ severityTextMap[record.severity] }}
              </a-tag>
            </template>
            <template v-if="column.key === 'status'">
              <span class="status-dot" :class="record.status === 'firing' ? 'dot-firing' : 'dot-resolved'"></span>
              {{ record.status === 'firing' ? '告警中' : '已恢复' }}
            </template>
            <template v-if="column.key === 'action'">
              <a-button type="link" size="small" @click="handleAck(record)" :disabled="record.status === 'resolved'">
                确认
              </a-button>
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { Dayjs } from 'dayjs'
import apiClient from '@/api/client'
import { message } from 'ant-design-vue'

const searchText = ref('')
const filterSeverity = ref<string>()
const filterService = ref<string>()
const filterStatus = ref<string>()
const dateRange = ref<[Dayjs, Dayjs]>()
const loading = ref(false)
const alerts = ref<any[]>([])
const stats = ref({ critical: 0, warning: 0, info: 0, resolved: 0 })

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const severityColorMap: Record<string, string> = {
  critical: 'red', warning: 'orange', info: 'blue',
}
const severityTextMap: Record<string, string> = {
  critical: '紧急', warning: '警告', info: '通知',
}

const columns = [
  { title: '告警时间', dataIndex: 'createdAt', key: 'createdAt', width: 180 },
  { title: '级别', key: 'severity', width: 100 },
  { title: '服务', dataIndex: 'service', key: 'service', width: 140 },
  { title: '告警内容', dataIndex: 'message', key: 'message', ellipsis: true },
  { title: '状态', key: 'status', width: 120 },
  { title: '恢复时间', dataIndex: 'resolvedAt', key: 'resolvedAt', width: 180 },
  { title: '操作', key: 'action', width: 100 },
]

const loadAlerts = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any>('/monitor/service-alerts', {
      params: {
        page: pagination.value.current,
        page_size: pagination.value.pageSize,
        search: searchText.value || undefined,
        severity: filterSeverity.value || undefined,
        service: filterService.value || undefined,
        status: filterStatus.value || undefined,
      },
    })
    alerts.value = res.items ?? []
    pagination.value.total = res.total ?? 0
    if (res.stats) stats.value = res.stats
  } catch {
    // API 未就绪
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadAlerts()
}

const handleAck = async (record: any) => {
  try {
    await apiClient.post(`/monitor/service-alerts/${record.id}/ack`)
    message.success('已确认告警')
    loadAlerts()
  } catch {
    message.error('操作失败')
  }
}

onMounted(() => { loadAlerts() })
</script>

<style scoped>
.service-alert-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.alert-stat-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  padding: 20px;
  text-align: center;
}
.alert-stat-value { font-size: 28px; font-weight: 700; line-height: 1.2; }
.alert-stat-label { font-size: 13px; color: var(--mxsec-text-3); margin-top: 4px; }

.dashboard-card {
  background: var(--mxsec-card-bg);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
}
.card-body { padding: 20px; }

.filter-bar {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 4px;
  border: 1px solid var(--mxsec-border);
}

.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 6px;
}
.dot-firing { background: #EF4444; box-shadow: 0 0 0 3px rgba(245,63,63,0.15); }
.dot-resolved { background: #22C55E; box-shadow: 0 0 0 3px rgba(0,180,42,0.15); }
</style>
