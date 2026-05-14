<template>
  <div class="remediation-tasks-page">
    <div class="page-header">
      <h2>修复任务</h2>
      <span class="page-header-hint">漏洞修复任务管理，确认后由 Agent 执行修复</span>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="[16, 16]" class="section-row">
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value">{{ taskStats.total ?? 0 }}</div>
          <div class="stat-label">总任务</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value warning">{{ taskStats.pending ?? 0 }}</div>
          <div class="stat-label">待确认</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value primary">{{ taskStats.confirmed ?? 0 }}</div>
          <div class="stat-label">已确认</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value processing">{{ taskStats.running ?? 0 }}</div>
          <div class="stat-label">执行中</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value success">{{ taskStats.success ?? 0 }}</div>
          <div class="stat-label">已完成</div>
        </div>
      </a-col>
      <a-col :xs="12" :md="4">
        <div class="stat-card">
          <div class="stat-value danger">{{ taskStats.failed ?? 0 }}</div>
          <div class="stat-label">失败</div>
        </div>
      </a-col>
    </a-row>

    <!-- 筛选和表格 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <a-select
            v-model:value="filterStatus"
            style="width: 140px"
            placeholder="任务状态"
            allow-clear
            @change="handleFilterChange"
          >
            <a-select-option value="pending">待确认</a-select-option>
            <a-select-option value="confirmed">已确认</a-select-option>
            <a-select-option value="running">执行中</a-select-option>
            <a-select-option value="success">已完成</a-select-option>
            <a-select-option value="failed">失败</a-select-option>
            <a-select-option value="cancelled">已取消</a-select-option>
          </a-select>
          <div class="filter-actions">
            <a-button @click="loadTasks">刷新</a-button>
          </div>
        </div>

        <div v-if="selectedRowKeys.length > 0" class="batch-action-bar">
          <span>已选择 {{ selectedRowKeys.length }} 项</span>
          <a-button
            v-if="selectedHasStatus('pending')"
            type="primary"
            size="small"
            :loading="batchConfirmLoading"
            @click="handleBatchConfirm"
          >
            批量确认
          </a-button>
          <a-button
            v-if="selectedHasStatus('failed')"
            size="small"
            :loading="batchRetryLoading"
            @click="handleBatchRetry"
          >
            批量重试
          </a-button>
          <a-button
            v-if="selectedHasStatus('pending') || selectedHasStatus('confirmed')"
            danger
            size="small"
            :loading="batchCancelLoading"
            @click="handleBatchCancel"
          >
            批量取消
          </a-button>
          <a-button size="small" @click="selectedRowKeys = []">取消选择</a-button>
        </div>

        <a-table
          :columns="columns"
          :data-source="tasks"
          :loading="loading"
          :pagination="pagination"
          size="middle"
          row-key="id"
          :row-selection="{ selectedRowKeys, onChange: onSelectChange, getCheckboxProps: (record: RemediationTaskItem) => ({ disabled: record.status === 'running' || record.status === 'success' }) }"
          @change="handleTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'cve'">
              <RouterLink :to="`/vuln-remediation/tasks/${record.id}`">{{ record.cveId }}</RouterLink>
            </template>
            <template v-else-if="column.key === 'host'">
              <RouterLink :to="`/hosts/${record.hostId}`">{{ record.hostname || record.hostId }}</RouterLink>
              <div class="text-muted">{{ record.ip }}</div>
            </template>
            <template v-else-if="column.key === 'status'">
              <a-tag :color="taskStatusColor(record.status)" :bordered="false">
                {{ taskStatusText(record.status) }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'command'">
              <a-tooltip :title="record.command">
                <code class="command-preview">{{ record.command?.slice(0, 40) }}{{ record.command?.length > 40 ? '...' : '' }}</code>
              </a-tooltip>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a-button
                  v-if="record.status === 'pending'"
                  type="link"
                  size="small"
                  @click="handleConfirm(record)"
                >
                  确认执行
                </a-button>
                <a-button
                  v-if="record.status === 'failed'"
                  type="link"
                  size="small"
                  @click="handleRetry(record)"
                >
                  重试
                </a-button>
                <a-button
                  v-if="record.status === 'pending' || record.status === 'confirmed'"
                  type="link"
                  size="small"
                  danger
                  @click="handleCancel(record)"
                >
                  取消
                </a-button>
                <RouterLink :to="`/vuln-remediation/tasks/${record.id}`">
                  <a-button type="link" size="small">详情</a-button>
                </RouterLink>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 确认执行弹窗 -->
    <a-modal
      v-model:open="confirmModalVisible"
      title="确认执行修复"
      @ok="doConfirm"
      :confirm-loading="confirmLoading"
    >
      <p>确认在主机 <strong>{{ confirmTask?.hostname }}</strong> 上执行以下修复命令？</p>
      <a-input
        v-model:value="confirmCommand"
        type="textarea"
        :rows="3"
        placeholder="修复命令"
      />
      <p class="confirm-warning">执行后将通过 Agent 远程执行该命令，请确认命令正确。</p>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { message } from 'ant-design-vue'
import { remediationTasksApi } from '@/api/remediation-tasks'
import type { RemediationTaskItem, RemediationTaskStats } from '@/api/remediation-tasks'

const loading = ref(false)
const tasks = ref<RemediationTaskItem[]>([])
const filterStatus = ref<string>()
const taskStats = ref<RemediationTaskStats>({})

const pagination = ref({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const confirmModalVisible = ref(false)
const confirmTask = ref<RemediationTaskItem | null>(null)
const confirmCommand = ref('')
const confirmLoading = ref(false)
const selectedRowKeys = ref<number[]>([])
const batchConfirmLoading = ref(false)
const batchRetryLoading = ref(false)
const batchCancelLoading = ref(false)

const columns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '漏洞', key: 'cve', width: 160 },
  { title: '目标主机', key: 'host', width: 180 },
  { title: '组件', dataIndex: 'component', width: 120 },
  { title: '修复命令', key: 'command', width: 220 },
  { title: '状态', key: 'status', width: 100 },
  { title: '创建时间', dataIndex: 'createdAt', width: 170 },
  { title: '操作', key: 'action', width: 180, fixed: 'right' },
]

const taskStatusColor = (status: string) => {
  const map: Record<string, string> = {
    pending: 'warning',
    confirmed: 'blue',
    running: 'processing',
    success: 'success',
    failed: 'error',
    cancelled: 'default',
  }
  return map[status] || 'default'
}

const taskStatusText = (status: string) => {
  const map: Record<string, string> = {
    pending: '待确认',
    confirmed: '已确认',
    running: '执行中',
    success: '已完成',
    failed: '失败',
    cancelled: '已取消',
  }
  return map[status] || status
}

const loadTasks = async () => {
  loading.value = true
  try {
    const res = await remediationTasksApi.list({
      page: pagination.value.current,
      page_size: pagination.value.pageSize,
      status: filterStatus.value,
    })
    tasks.value = res.items ?? []
    pagination.value.total = res.total ?? 0
  } catch {
    tasks.value = []
  } finally {
    loading.value = false
  }
}

const loadStats = async () => {
  try {
    taskStats.value = await remediationTasksApi.getStats()
  } catch {
    // ignore
  }
}

const handleFilterChange = () => {
  pagination.value.current = 1
  loadTasks()
}

const handleTableChange = (pag: any) => {
  pagination.value.current = pag.current
  pagination.value.pageSize = pag.pageSize
  loadTasks()
}

const handleConfirm = (record: RemediationTaskItem) => {
  confirmTask.value = record
  confirmCommand.value = record.command
  confirmModalVisible.value = true
}

const doConfirm = async () => {
  if (!confirmTask.value) return
  confirmLoading.value = true
  try {
    await remediationTasksApi.confirm(confirmTask.value.id, confirmCommand.value)
    message.success('任务已确认，等待 Agent 执行')
    confirmModalVisible.value = false
    loadTasks()
    loadStats()
  } catch {
    message.error('确认失败')
  } finally {
    confirmLoading.value = false
  }
}

const handleRetry = async (record: RemediationTaskItem) => {
  try {
    await remediationTasksApi.retry(record.id)
    message.success('任务已重置为待确认状态')
    loadTasks()
    loadStats()
  } catch {
    message.error('重试失败')
  }
}

const handleCancel = async (record: RemediationTaskItem) => {
  try {
    await remediationTasksApi.cancel(record.id)
    message.success('任务已取消')
    loadTasks()
    loadStats()
  } catch {
    message.error('取消失败')
  }
}

const onSelectChange = (keys: number[]) => {
  selectedRowKeys.value = keys
}

const selectedHasStatus = (status: string) => {
  return tasks.value.some(t => selectedRowKeys.value.includes(t.id) && t.status === status)
}

const handleBatchConfirm = async () => {
  if (selectedRowKeys.value.length === 0) return
  batchConfirmLoading.value = true
  try {
    const ids = tasks.value
      .filter(t => selectedRowKeys.value.includes(t.id) && t.status === 'pending')
      .map(t => t.id)
    const res = await remediationTasksApi.batchConfirm(ids)
    message.success(`已确认 ${res.confirmed} 个任务，等待 Agent 执行`)
    selectedRowKeys.value = []
    loadTasks()
    loadStats()
  } catch {
    message.error('批量确认失败')
  } finally {
    batchConfirmLoading.value = false
  }
}

const handleBatchRetry = async () => {
  if (selectedRowKeys.value.length === 0) return
  batchRetryLoading.value = true
  try {
    const ids = tasks.value
      .filter(t => selectedRowKeys.value.includes(t.id) && t.status === 'failed')
      .map(t => t.id)
    const res = await remediationTasksApi.batchRetry(ids)
    message.success(`已重试 ${res.retried} 个任务`)
    selectedRowKeys.value = []
    loadTasks()
    loadStats()
  } catch {
    message.error('批量重试失败')
  } finally {
    batchRetryLoading.value = false
  }
}

const handleBatchCancel = async () => {
  if (selectedRowKeys.value.length === 0) return
  batchCancelLoading.value = true
  try {
    const ids = tasks.value
      .filter(t => selectedRowKeys.value.includes(t.id) && (t.status === 'pending' || t.status === 'confirmed'))
      .map(t => t.id)
    const res = await remediationTasksApi.batchCancel(ids)
    message.success(`已取消 ${res.cancelled} 个任务`)
    selectedRowKeys.value = []
    loadTasks()
    loadStats()
  } catch {
    message.error('批量取消失败')
  } finally {
    batchCancelLoading.value = false
  }
}

onMounted(() => {
  loadTasks()
  loadStats()
})
</script>

<style scoped>
.remediation-tasks-page { width: 100%; }
.section-row { margin-bottom: 16px; }

.stat-card {
  background: #FFFFFF;
  border: 1px solid #E5E8EF;
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.stat-value { font-size: 24px; font-weight: 700; color: #1D2129; }
.stat-value.warning { color: #FF7D00; }
.stat-value.primary { color: #165DFF; }
.stat-value.processing { color: #722ED1; }
.stat-value.success { color: #52C41A; }
.stat-value.danger { color: #F53F3F; }

.stat-label { margin-top: 4px; font-size: 12px; color: #86909C; }

.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 12px; margin-bottom: 16px; }
.filter-actions { margin-left: auto; }

.batch-action-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: #E8F3FF;
  border: 1px solid #BEDAFF;
  border-radius: 6px;
  font-size: 13px;
}

.command-preview {
  font-family: 'SF Mono', 'Monaco', monospace;
  font-size: 12px;
  color: #4E5969;
}

.text-muted { font-size: 12px; color: #86909C; }



.confirm-warning {
  margin-top: 12px;
  color: #FF7D00;
  font-size: 13px;
}
</style>
