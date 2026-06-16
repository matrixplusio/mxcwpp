<template>
  <div class="fix-history-page">
    <div class="page-header">
      <h2>修复任务历史</h2>
      <a-space>
        <a-button @click="handleRefresh" :loading="loading">
          <template #icon>
            <ReloadOutlined />
          </template>
          刷新
        </a-button>
      </a-space>
    </div>

    <!-- 筛选条件 -->
    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-form layout="inline" :model="filters">
        <a-form-item label="状态">
          <a-select
            v-model:value="filters.status"
            placeholder="选择状态"
            style="width: 150px"
            allow-clear
          >
            <a-select-option value="pending">待执行</a-select-option>
            <a-select-option value="running">执行中</a-select-option>
            <a-select-option value="completed">已完成</a-select-option>
            <a-select-option value="failed">失败</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item>
          <a-button type="primary" @click="handleSearch">
            <template #icon>
              <SearchOutlined />
            </template>
            查询
          </a-button>
          <a-button style="margin-left: 8px" @click="handleReset">重置</a-button>
        </a-form-item>
      </a-form>
    </a-card>

    <!-- 任务列表 -->
    <a-table
      :columns="columns"
      :data-source="tasks"
      :loading="loading"
      :pagination="pagination"
      @change="handleTableChange"
      row-key="task_id"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)">
            <template #icon v-if="record.status === 'running'">
              <SyncOutlined spin />
            </template>
            {{ getStatusText(record.status) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'progress'">
          <a-progress
            :percent="record.progress"
            :status="record.status === 'completed' ? 'success' : record.status === 'failed' ? 'exception' : 'active'"
            :show-info="true"
          />
        </template>
        <template v-else-if="column.key === 'result'">
          <a-space>
            <span style="color: #22C55E">成功: {{ record.success_count }}</span>
            <span style="color: #EF4444">失败: {{ record.failed_count }}</span>
          </a-space>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space size="small">
            <a-button type="link" size="small" @click="handleViewDetail(record)">
              查看详情
            </a-button>
            <a-popconfirm
              v-if="isAdmin && record.status !== 'running'"
              title="确定要删除此任务吗？"
              ok-text="确定"
              cancel-text="取消"
              @confirm="handleDelete(record)"
            >
              <a-button type="link" size="small" danger>
                删除
              </a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 任务详情 Modal -->
    <a-modal
      v-model:open="detailModalVisible"
      title="修复任务详情"
      width="1200px"
      :footer="null"
    >
      <a-descriptions v-if="selectedTask" :column="2" bordered size="small">
        <a-descriptions-item label="任务ID" :span="2">
          <span style="font-family: monospace;">{{ selectedTask.task_id }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="状态">
          <a-tag :color="getStatusColor(selectedTask.status)">
            {{ getStatusText(selectedTask.status) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="进度">
          <a-progress :percent="selectedTask.progress" />
        </a-descriptions-item>
        <a-descriptions-item label="总计">
          {{ selectedTask.total_count }}
        </a-descriptions-item>
        <a-descriptions-item label="成功">
          <span style="color: #22C55E">{{ selectedTask.success_count }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="失败">
          <span style="color: #EF4444">{{ selectedTask.failed_count }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="创建时间">
          {{ formatTime(selectedTask.created_at) }}
        </a-descriptions-item>
        <a-descriptions-item label="完成时间">
          {{ formatTime(selectedTask.completed_at) || '-' }}
        </a-descriptions-item>
      </a-descriptions>

      <!-- 标签页：主机状态和修复结果 -->
      <a-tabs v-model:activeKey="activeTab" style="margin-top: 16px">
        <!-- 主机状态标签页 -->
        <a-tab-pane key="hosts" tab="主机状态">
          <a-table
            :columns="hostStatusColumns"
            :data-source="hostStatuses"
            :loading="hostStatusLoading"
            :pagination="hostStatusPagination"
            @change="handleHostStatusTableChange"
            row-key="id"
            size="small"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="getHostStatusColor(record.status)">
                  <template #icon v-if="record.status === 'dispatched'">
                    <SyncOutlined spin />
                  </template>
                  {{ getHostStatusText(record.status) }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'error_message'">
                <a-tooltip v-if="record.error_message" :title="record.error_message">
                  <span class="error-text">{{ record.error_message.slice(0, 50) }}{{ record.error_message.length > 50 ? '...' : '' }}</span>
                </a-tooltip>
                <span v-else>-</span>
              </template>
            </template>
          </a-table>
        </a-tab-pane>

        <!-- 修复结果标签页 -->
        <a-tab-pane key="results" tab="修复结果">
          <a-table
            :columns="resultColumns"
            :data-source="fixResults"
            :loading="resultsLoading"
            :pagination="resultPagination"
            @change="handleResultTableChange"
            :row-key="(record: any) => record.task_id + '_' + record.host_id + '_' + record.rule_id"
            size="small"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="record.status === 'success' ? 'green' : record.status === 'failed' ? 'red' : 'default'">
                  {{ record.status === 'success' ? '成功' : record.status === 'failed' ? '失败' : '跳过' }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'output'">
                <a-tooltip v-if="record.output" :title="record.output">
                  <span class="output-text">{{ record.output.slice(0, 50) }}{{ record.output.length > 50 ? '...' : '' }}</span>
                </a-tooltip>
                <span v-else>-</span>
              </template>
              <template v-else-if="column.key === 'error_msg'">
                <a-tooltip v-if="record.error_msg" :title="record.error_msg">
                  <span class="error-text">{{ record.error_msg.slice(0, 50) }}{{ record.error_msg.length > 50 ? '...' : '' }}</span>
                </a-tooltip>
                <span v-else>-</span>
              </template>
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import { message } from 'ant-design-vue'
import {
  ReloadOutlined,
  SearchOutlined,
  SyncOutlined,
} from '@ant-design/icons-vue'
import { fixApi } from '@/api/fix'
import { useAuthStore } from '@/stores/auth'
import type { FixTask, FixResult, FixTaskHostStatus } from '@/api/types'

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const loading = ref(false)
const tasks = ref<FixTask[]>([])
const filters = reactive({
  status: undefined as string | undefined,
})
const detailModalVisible = ref(false)
const selectedTask = ref<FixTask | null>(null)
const fixResults = ref<FixResult[]>([])
const resultsLoading = ref(false)
const hostStatuses = ref<FixTaskHostStatus[]>([])
const hostStatusLoading = ref(false)
const activeTab = ref('hosts')

// 自动刷新定时器
let refreshTimer: ReturnType<typeof setInterval> | null = null

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const resultPagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const hostStatusPagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: '任务ID',
    dataIndex: 'task_id',
    key: 'task_id',
    width: 180,
    ellipsis: true,
    customRender: ({ text }: { text: string }) => text ? `${text.slice(0, 8)}...` : '-',
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
  },
  {
    title: '进度',
    key: 'progress',
    width: 150,
  },
  {
    title: '修复结果',
    key: 'result',
    width: 180,
  },
  {
    title: '总计',
    dataIndex: 'total_count',
    key: 'total_count',
    width: 80,
  },
  {
    title: '创建时间',
    dataIndex: 'created_at',
    key: 'created_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text),
  },
  {
    title: '完成时间',
    dataIndex: 'completed_at',
    key: 'completed_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text) || '-',
  },
  {
    title: '操作',
    key: 'action',
    width: 150,
    fixed: 'right' as const,
  },
]

const resultColumns = [
  {
    title: '主机ID',
    dataIndex: 'host_id',
    key: 'host_id',
    width: 120,
    ellipsis: true,
    customRender: ({ text }: { text: string }) => text ? `${text.slice(0, 8)}...` : '-',
  },
  {
    title: '规则ID',
    dataIndex: 'rule_id',
    key: 'rule_id',
    width: 150,
    ellipsis: true,
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
  },
  {
    title: '修复命令',
    dataIndex: 'command',
    key: 'command',
    ellipsis: true,
  },
  {
    title: '输出',
    key: 'output',
    width: 200,
    ellipsis: true,
  },
  {
    title: '错误信息',
    key: 'error_msg',
    width: 200,
    ellipsis: true,
  },
  {
    title: '修复时间',
    dataIndex: 'fixed_at',
    key: 'fixed_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text),
  },
]

const hostStatusColumns = [
  {
    title: '主机名',
    dataIndex: 'hostname',
    key: 'hostname',
    width: 150,
  },
  {
    title: 'IP地址',
    dataIndex: 'ip_address',
    key: 'ip_address',
    width: 130,
  },
  {
    title: '业务线',
    dataIndex: 'business_line',
    key: 'business_line',
    width: 120,
  },
  {
    title: '操作系统',
    key: 'os',
    width: 150,
    customRender: ({ record }: { record: FixTaskHostStatus }) =>
      `${record.os_family} ${record.os_version}`,
  },
  {
    title: '运行环境',
    dataIndex: 'runtime_type',
    key: 'runtime_type',
    width: 100,
  },
  {
    title: '状态',
    key: 'status',
    width: 100,
  },
  {
    title: '下发时间',
    dataIndex: 'dispatched_at',
    key: 'dispatched_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text),
  },
  {
    title: '完成时间',
    dataIndex: 'completed_at',
    key: 'completed_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text) || '-',
  },
  {
    title: '错误信息',
    key: 'error_message',
    width: 200,
    ellipsis: true,
  },
]

const loadTasks = async () => {
  loading.value = true
  try {
    const response = await fixApi.listFixTasks({
      page: pagination.current,
      page_size: pagination.pageSize,
      status: filters.status,
    })
    tasks.value = response.items || []
    pagination.total = response.total || 0
  } catch (error) {
    console.error('加载修复任务列表失败:', error)
  } finally {
    loading.value = false
  }
}

const loadFixResults = async (taskId: string) => {
  resultsLoading.value = true
  try {
    const response = await fixApi.getFixResults(taskId, {
      page: resultPagination.current,
      page_size: resultPagination.pageSize,
    })
    fixResults.value = response.items || []
    resultPagination.total = response.total || 0
  } catch (error) {
    console.error('加载修复结果失败:', error)
  } finally {
    resultsLoading.value = false
  }
}

const loadHostStatuses = async (taskId: string) => {
  hostStatusLoading.value = true
  try {
    const response = await fixApi.getFixTaskHostStatus(taskId, {
      page: hostStatusPagination.current,
      page_size: hostStatusPagination.pageSize,
    })
    hostStatuses.value = response.items || []
    hostStatusPagination.total = response.total || 0
  } catch (error) {
    console.error('加载主机状态失败:', error)
  } finally {
    hostStatusLoading.value = false
  }
}

const handleSearch = () => {
  pagination.current = 1
  loadTasks()
}

const handleReset = () => {
  filters.status = undefined
  pagination.current = 1
  loadTasks()
}

const handleRefresh = () => {
  loadTasks()
  message.success('已刷新')
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadTasks()
}

const handleResultTableChange = (pag: any) => {
  resultPagination.current = pag.current
  resultPagination.pageSize = pag.pageSize
  if (selectedTask.value) {
    loadFixResults(selectedTask.value.task_id)
  }
}

const handleHostStatusTableChange = (pag: any) => {
  hostStatusPagination.current = pag.current
  hostStatusPagination.pageSize = pag.pageSize
  if (selectedTask.value) {
    loadHostStatuses(selectedTask.value.task_id)
  }
}

const handleViewDetail = async (record: FixTask) => {
  selectedTask.value = record
  detailModalVisible.value = true
  activeTab.value = 'hosts'
  hostStatusPagination.current = 1
  resultPagination.current = 1
  await loadHostStatuses(record.task_id)
}

const handleDelete = async (record: FixTask) => {
  try {
    await fixApi.deleteFixTask(record.task_id)
    message.success('删除成功')
    loadTasks()
  } catch (error) {
    console.error('删除失败:', error)
  }
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    pending: 'default',
    running: 'processing',
    completed: 'success',
    failed: 'error',
  }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = {
    pending: '待执行',
    running: '执行中',
    completed: '已完成',
    failed: '失败',
  }
  return texts[status] || status
}

const getHostStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    dispatched: 'processing',
    completed: 'success',
    timeout: 'warning',
    failed: 'error',
  }
  return colors[status] || 'default'
}

const getHostStatusText = (status: string) => {
  const texts: Record<string, string> = {
    dispatched: '已下发',
    completed: '已完成',
    timeout: '超时',
    failed: '失败',
  }
  return texts[status] || status
}

const formatTime = (time: string | undefined) => {
  if (!time) return ''
  const date = new Date(time)
  if (isNaN(date.getTime())) return time
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

// 自动刷新（当有任务执行中时）
const startAutoRefresh = () => {
  if (refreshTimer) return
  refreshTimer = setInterval(() => {
    const hasRunning = tasks.value.some(t => t.status === 'running')
    if (hasRunning) {
      loadTasks()
    } else {
      stopAutoRefresh()
    }
  }, 5000)
}

const stopAutoRefresh = () => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

// 监听标签页切换
watch(activeTab, (newTab) => {
  if (!selectedTask.value) return
  if (newTab === 'hosts' && hostStatuses.value.length === 0) {
    loadHostStatuses(selectedTask.value.task_id)
  } else if (newTab === 'results' && fixResults.value.length === 0) {
    loadFixResults(selectedTask.value.task_id)
  }
})

onMounted(() => {
  loadTasks()
  startAutoRefresh()
})

onUnmounted(() => {
  stopAutoRefresh()
})
</script>

<style scoped>
.fix-history-page {
  width: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.output-text {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  color: #595959;
  background: #f5f7fa;
  padding: 8px 12px;
  border-radius: 4px;
  display: block;
}

.error-text {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  color: #EF4444;
  background: var(--mxsec-card-bg)2f0;
  padding: 8px 12px;
  border-radius: 4px;
  display: block;
}
</style>
