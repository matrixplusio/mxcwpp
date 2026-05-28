<template>
  <div class="audit-log-page">
    <div class="page-header">
      <h2>审计日志</h2>
      <span class="page-header-hint">记录用户关键操作行为，确保合规可追溯</span>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-input
            v-model:value="filters.username"
            placeholder="操作用户"
            style="width: 160px"
            allow-clear
            @press-enter="loadLogs"
          />
          <a-select v-model:value="filters.resource_type" style="width: 160px" placeholder="操作模块" allow-clear @change="loadLogs">
            <a-select-option value="hosts">主机管理</a-select-option>
            <a-select-option value="policies">策略管理</a-select-option>
            <a-select-option value="rules">规则管理</a-select-option>
            <a-select-option value="tasks">任务管理</a-select-option>
            <a-select-option value="users">用户管理</a-select-option>
            <a-select-option value="alerts">告警管理</a-select-option>
            <a-select-option value="notifications">通知配置</a-select-option>
            <a-select-option value="system-config">系统配置</a-select-option>
            <a-select-option value="fim-policies">FIM 策略</a-select-option>
          </a-select>
          <a-select v-model:value="filters.action" style="width: 120px" placeholder="操作类型" allow-clear @change="loadLogs">
            <a-select-option value="POST">创建/执行</a-select-option>
            <a-select-option value="PUT">更新</a-select-option>
            <a-select-option value="DELETE">删除</a-select-option>
          </a-select>
          <a-button @click="loadLogs">搜索</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="logs"
          :loading="loading"
          :pagination="pagination"
          row-key="id"
          @change="handleTableChange"
          size="middle"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'action'">
              <a-tag :color="actionColor[record.action]">
                {{ actionText[record.action] || record.action }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'status_code'">
              <a-tag :color="record.status_code < 400 ? 'green' : 'red'">
                {{ record.status_code }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'resource'">
              <span>{{ record.resource_type }}</span>
              <span v-if="record.resource_id" style="color: #86909C;"> / {{ record.resource_id }}</span>
            </template>
          </template>
        </a-table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import apiClient from '@/api/client'

interface AuditLog {
  id: number
  username: string
  action: string
  resource_type: string
  resource_id: string
  path: string
  ip: string
  status_code: number
  created_at: string
}

const filters = ref({
  username: '',
  resource_type: undefined as string | undefined,
  action: undefined as string | undefined,
})
const loading = ref(false)
const logs = ref<AuditLog[]>([])
const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const actionColor: Record<string, string> = {
  POST: 'green',
  PUT: 'blue',
  DELETE: 'red',
}
const actionText: Record<string, string> = {
  POST: '创建/执行',
  PUT: '更新',
  DELETE: '删除',
}

const columns = [
  { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
  { title: '用户', dataIndex: 'username', key: 'username', width: 120 },
  { title: '操作类型', key: 'action', width: 110 },
  { title: '资源', key: 'resource', width: 200 },
  { title: '请求路径', dataIndex: 'path', key: 'path', ellipsis: true },
  { title: 'IP 地址', dataIndex: 'ip', key: 'ip', width: 140 },
  { title: '状态码', key: 'status_code', width: 90 },
]

const loadLogs = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<{ items: AuditLog[]; total: number }>('/audit-logs', {
      params: {
        page: pagination.value.current,
        page_size: pagination.value.pageSize,
        username: filters.value.username || undefined,
        resource_type: filters.value.resource_type || undefined,
        action: filters.value.action || undefined,
      },
    })
    logs.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch {
    logs.value = []
  } finally {
    loading.value = false
  }
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadLogs()
}

onMounted(() => { loadLogs() })
</script>

<style scoped>
.audit-log-page { width: 100%; }

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
}
</style>
