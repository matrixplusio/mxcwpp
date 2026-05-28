<template>
  <div class="log-query-page">
    <div class="page-header">
      <h2>日志查询</h2>
      <span class="page-header-hint">查询系统运行日志与审计日志</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <!-- 筛选栏 -->
        <div class="filter-bar">
          <a-select v-model:value="filterSource" style="width: 160px" placeholder="日志来源" @change="loadLogs">
            <a-select-option value="manager">Manager</a-select-option>
            <a-select-option value="agentcenter">AgentCenter</a-select-option>
            <a-select-option value="agent">Agent</a-select-option>
          </a-select>
          <a-select v-model:value="filterLevel" style="width: 120px" placeholder="日志级别" allow-clear @change="loadLogs">
            <a-select-option value="error">ERROR</a-select-option>
            <a-select-option value="warn">WARN</a-select-option>
            <a-select-option value="info">INFO</a-select-option>
            <a-select-option value="debug">DEBUG</a-select-option>
          </a-select>
          <a-input-search
            v-model:value="searchText"
            placeholder="搜索关键词"
            style="width: 280px"
            allow-clear
            @search="loadLogs"
          />
          <a-range-picker
            v-model:value="dateRange"
            show-time
            style="width: 340px"
            @change="loadLogs"
          />
          <a-button type="primary" @click="loadLogs">查询</a-button>
        </div>

        <!-- 日志列表 -->
        <a-table
          :columns="columns"
          :data-source="logs"
          :loading="loading"
          :pagination="pagination"
          @change="handleTableChange"
          size="small"
          row-key="id"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'level'">
              <a-tag :color="levelColorMap[record.level]" :bordered="false">
                {{ record.level?.toUpperCase() }}
              </a-tag>
            </template>
            <template v-if="column.key === 'message'">
              <div class="log-message" @click="showLogDetail(record)">
                {{ record.message }}
              </div>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 日志详情 Drawer -->
    <a-drawer
      v-model:open="showDetail"
      title="日志详情"
      width="640"
      placement="right"
    >
      <template v-if="detailRecord">
        <a-descriptions :column="1" bordered size="small">
          <a-descriptions-item label="时间">{{ detailRecord.timestamp }}</a-descriptions-item>
          <a-descriptions-item label="级别">
            <a-tag :color="levelColorMap[detailRecord.level]" :bordered="false">{{ detailRecord.level?.toUpperCase() }}</a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="来源">{{ detailRecord.source }}</a-descriptions-item>
          <a-descriptions-item label="模块">{{ detailRecord.module }}</a-descriptions-item>
          <a-descriptions-item label="消息">{{ detailRecord.message }}</a-descriptions-item>
        </a-descriptions>
        <a-divider>详细数据</a-divider>
        <pre class="log-json">{{ JSON.stringify(detailRecord.data, null, 2) }}</pre>
      </template>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import type { Dayjs } from 'dayjs'
import apiClient from '@/api/client'

const filterSource = ref('manager')
const filterLevel = ref<string>()
const searchText = ref('')
const dateRange = ref<[Dayjs, Dayjs]>()
const loading = ref(false)
const logs = ref<any[]>([])

const showDetail = ref(false)
const detailRecord = ref<any>(null)

const pagination = ref({
  current: 1, pageSize: 50, total: 0, showSizeChanger: true,
  pageSizeOptions: ['50', '100', '200'],
  showTotal: (total: number) => `共 ${total} 条`,
})

const levelColorMap: Record<string, string> = {
  error: 'red', warn: 'orange', info: 'blue', debug: 'default',
}

const columns = [
  { title: '时间', dataIndex: 'timestamp', key: 'timestamp', width: 200 },
  { title: '级别', key: 'level', width: 80 },
  { title: '来源', dataIndex: 'source', key: 'source', width: 120 },
  { title: '模块', dataIndex: 'module', key: 'module', width: 140 },
  { title: '消息', key: 'message' },
]

const loadLogs = async () => {
  loading.value = true
  try {
    const params: any = {
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      source: filterSource.value,
      level: filterLevel.value || undefined,
      search: searchText.value || undefined,
    }
    if (dateRange.value && dateRange.value[0] && dateRange.value[1]) {
      params.start_time = dateRange.value[0].toISOString()
      params.end_time = dateRange.value[1].toISOString()
    }
    const res = await apiClient.get<any>('/system/logs', { params })
    logs.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch { logs.value = [] }
  finally { loading.value = false }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadLogs()
}

const showLogDetail = (record: any) => {
  detailRecord.value = record
  showDetail.value = true
}

onMounted(() => { loadLogs() })
</script>

<style scoped>
.log-query-page { width: 100%; }

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
  flex-wrap: wrap;
}

.log-message {
  cursor: pointer;
  font-family: 'SF Mono', 'Consolas', monospace;
  font-size: 12px;
  color: var(--mxsec-text-2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.log-message:hover { color: var(--mxsec-primary); }

.log-json {
  background: var(--mxsec-fill-1);
  padding: 16px;
  border-radius: 4px;
  font-size: 12px;
  font-family: 'SF Mono', 'Consolas', monospace;
  overflow-x: auto;
  max-height: 400px;
  color: var(--mxsec-text-1);
}
</style>
