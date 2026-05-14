<template>
  <div class="fim-tasks">
    <div class="page-header">
      <h2>FIM 任务管理</h2>
      <a-button type="primary" @click="showCreateModal">
        <PlusOutlined /> 创建任务
      </a-button>
    </div>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-select
        v-model:value="filters.status"
        placeholder="任务状态"
        style="width: 140px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="pending">待执行</a-select-option>
        <a-select-option value="running">执行中</a-select-option>
        <a-select-option value="completed">已完成</a-select-option>
        <a-select-option value="failed">失败</a-select-option>
      </a-select>
      <a-button style="margin-left: 8px" @click="fetchTasks">
        <ReloadOutlined /> 刷新
      </a-button>
    </div>

    <!-- 任务表格 -->
    <a-table
      :columns="columns"
      :data-source="tasks"
      :loading="loading"
      :pagination="pagination"
      row-key="task_id"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'task_id'">
          <a @click="showTaskDetail(record)">
            {{ record.task_id.substring(0, 8) }}...
          </a>
        </template>
        <template v-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)">
            {{ getStatusText(record.status) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'progress'">
          <template v-if="record.dispatched_host_count > 0">
            <a-progress
              :percent="Math.round((record.completed_host_count / record.dispatched_host_count) * 100)"
              :status="record.status === 'failed' ? 'exception' : record.status === 'completed' ? 'success' : 'active'"
              size="small"
            />
          </template>
          <span v-else>-</span>
        </template>
        <template v-if="column.key === 'host_count'">
          {{ record.completed_host_count }} / {{ record.dispatched_host_count }}
        </template>
        <template v-if="column.key === 'total_events'">
          <span :style="{ color: record.total_events > 0 ? '#fa541c' : '#00B42A', fontWeight: 600 }">
            {{ record.total_events }}
          </span>
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a v-if="record.status === 'pending'" @click="handleRun(record)">执行</a>
            <a @click="showTaskDetail(record)">详情</a>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 创建任务弹窗 -->
    <a-modal
      v-model:open="createVisible"
      title="创建 FIM 检查任务"
      :confirm-loading="createLoading"
      @ok="handleCreateTask"
    >
      <a-form layout="vertical">
        <a-form-item label="选择策略" required>
          <a-select
            v-model:value="createForm.policy_id"
            placeholder="选择 FIM 策略"
            :loading="policiesLoading"
            show-search
            :filter-option="filterOption"
          >
            <a-select-option
              v-for="p in availablePolicies"
              :key="p.policy_id"
              :value="p.policy_id"
            >
              {{ p.name }}
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="目标范围">
          <a-select v-model:value="createForm.target_type">
            <a-select-option value="">使用策略默认</a-select-option>
            <a-select-option value="all">所有主机</a-select-option>
            <a-select-option value="host_ids">指定主机</a-select-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 任务详情弹窗 -->
    <a-modal
      v-model:open="detailVisible"
      title="任务详情"
      :width="720"
      :footer="null"
    >
      <template v-if="selectedTask">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="任务 ID" :span="2">
            <span style="font-family: monospace; font-size: 12px">{{ selectedTask.task_id }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="策略 ID">
            <span style="font-family: monospace; font-size: 12px">{{ selectedTask.policy_id }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="getStatusColor(selectedTask.status)">
              {{ getStatusText(selectedTask.status) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="下发主机数">{{ selectedTask.dispatched_host_count }}</a-descriptions-item>
          <a-descriptions-item label="完成主机数">{{ selectedTask.completed_host_count }}</a-descriptions-item>
          <a-descriptions-item label="变更事件数">
            <span style="color: #fa541c; font-weight: 600">{{ selectedTask.total_events }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="创建时间">{{ selectedTask.created_at }}</a-descriptions-item>
          <a-descriptions-item label="执行时间">{{ selectedTask.executed_at || '-' }}</a-descriptions-item>
          <a-descriptions-item label="完成时间">{{ selectedTask.completed_at || '-' }}</a-descriptions-item>
        </a-descriptions>

        <template v-if="taskHostStatuses.length > 0">
          <a-divider>主机执行状态</a-divider>
          <a-table
            :columns="hostStatusColumns"
            :data-source="taskHostStatuses"
            :pagination="false"
            size="small"
            row-key="id"
          >
            <template #bodyCell="{ column, record: hr }">
              <template v-if="column.key === 'host_status'">
                <a-tag :color="getStatusColor(hr.status)">{{ getStatusText(hr.status) }}</a-tag>
              </template>
              <template v-if="column.key === 'changes'">
                <span v-if="hr.added_count" style="color: #00B42A">+{{ hr.added_count }}</span>
                <span v-if="hr.changed_count" style="color: #FF7D00; margin-left: 4px">~{{ hr.changed_count }}</span>
                <span v-if="hr.removed_count" style="color: #F53F3F; margin-left: 4px">-{{ hr.removed_count }}</span>
                <span v-if="!hr.added_count && !hr.changed_count && !hr.removed_count">-</span>
              </template>
              <template v-if="column.key === 'run_time'">
                {{ hr.run_time_sec > 0 ? formatDuration(hr.run_time_sec) : '-' }}
              </template>
            </template>
          </a-table>
        </template>
      </template>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { fimApi } from '@/api/fim'
import type { FIMTask, FIMTaskHostStatus, FIMPolicy } from '@/api/types'

const loading = ref(false)
const tasks = ref<FIMTask[]>([])
const createVisible = ref(false)
const createLoading = ref(false)
const detailVisible = ref(false)
const selectedTask = ref<FIMTask | null>(null)
const taskHostStatuses = ref<FIMTaskHostStatus[]>([])
const availablePolicies = ref<FIMPolicy[]>([])
const policiesLoading = ref(false)

const filters = reactive({
  status: undefined as string | undefined,
})

const createForm = reactive({
  policy_id: '',
  target_type: '',
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '任务 ID', key: 'task_id', width: 120 },
  { title: '状态', key: 'status', width: 90, align: 'center' as const },
  { title: '进度', key: 'progress', width: 180 },
  { title: '主机完成', key: 'host_count', width: 100, align: 'center' as const },
  { title: '事件数', key: 'total_events', width: 80, align: 'center' as const },
  { title: '创建时间', dataIndex: 'created_at', width: 170 },
  { title: '完成时间', dataIndex: 'completed_at', width: 170 },
  { title: '操作', key: 'action', width: 120 },
]

const hostStatusColumns = [
  { title: '主机名', dataIndex: 'hostname', width: 150 },
  { title: '状态', key: 'host_status', width: 90 },
  { title: '扫描条目', dataIndex: 'total_entries', width: 90 },
  { title: '变更', key: 'changes', width: 120 },
  { title: '耗时', key: 'run_time', width: 80 },
  { title: '错误信息', dataIndex: 'error_message', ellipsis: true },
]

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    pending: 'default',
    running: 'processing',
    completed: 'success',
    failed: 'error',
    dispatched: 'processing',
    timeout: 'warning',
  }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = {
    pending: '待执行',
    running: '执行中',
    completed: '已完成',
    failed: '失败',
    dispatched: '已下发',
    timeout: '超时',
  }
  return texts[status] || status
}

const formatDuration = (seconds: number) => {
  if (seconds < 60) return `${seconds}s`
  const mins = Math.floor(seconds / 60)
  const secs = seconds % 60
  return `${mins}m ${secs}s`
}

const filterOption = (input: string, option: any) => {
  return option.children?.[0]?.children?.toLowerCase().includes(input.toLowerCase())
}

const fetchTasks = async () => {
  loading.value = true
  try {
    const res = await fimApi.listTasks({
      page: pagination.current,
      page_size: pagination.pageSize,
      status: filters.status,
    })
    tasks.value = res.items || []
    pagination.total = res.total
  } catch {
    // API 客户端已处理错误提示
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  pagination.current = 1
  fetchTasks()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchTasks()
}

const fetchPolicies = async () => {
  policiesLoading.value = true
  try {
    const res = await fimApi.listPolicies({ page: 1, page_size: 100, enabled: 'true' })
    availablePolicies.value = res.items || []
  } catch {
    // 静默处理
  } finally {
    policiesLoading.value = false
  }
}

const showCreateModal = () => {
  createForm.policy_id = ''
  createForm.target_type = ''
  fetchPolicies()
  createVisible.value = true
}

const handleCreateTask = async () => {
  if (!createForm.policy_id) {
    message.warning('请选择策略')
    return
  }
  createLoading.value = true
  try {
    const data: any = { policy_id: createForm.policy_id }
    if (createForm.target_type) {
      data.target_type = createForm.target_type
    }
    await fimApi.createTask(data)
    message.success('任务创建成功')
    createVisible.value = false
    fetchTasks()
  } catch {
    // API 客户端已处理错误提示
  } finally {
    createLoading.value = false
  }
}

const handleRun = async (task: FIMTask) => {
  try {
    await fimApi.runTask(task.task_id)
    message.success('任务已开始执行')
    fetchTasks()
  } catch {
    // API 客户端已处理错误提示
  }
}

const showTaskDetail = async (task: FIMTask) => {
  try {
    const res = await fimApi.getTask(task.task_id)
    selectedTask.value = res.task
    taskHostStatuses.value = res.host_statuses || []
    detailVisible.value = true
  } catch {
    // API 客户端已处理错误提示
  }
}

// 自动刷新：有运行中的任务时轮询
let refreshTimer: ReturnType<typeof setInterval> | null = null

const startAutoRefresh = () => {
  if (refreshTimer) return
  refreshTimer = setInterval(() => {
    const hasRunning = tasks.value.some((t) => t.status === 'running')
    if (hasRunning) {
      fetchTasks()
    }
  }, 5000)
}

onMounted(() => {
  fetchTasks()
  startAutoRefresh()
})

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
})
</script>

<style scoped>
.fim-tasks {
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

.filter-bar {
  display: flex;
  align-items: center;
  margin-bottom: 16px;
}
</style>
