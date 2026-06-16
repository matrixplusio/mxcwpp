<template>
  <div class="tasks-page">
    <div class="page-header">
      <h2>任务执行</h2>
      <a-space>
        <a-button
          v-if="isAdmin && selectedRowKeys.length > 0"
          type="primary"
          @click="handleBatchRun"
          :loading="batchRunning"
        >
          <template #icon>
            <PlayCircleOutlined />
          </template>
          批量执行 ({{ selectedRowKeys.length }})
        </a-button>
        <a-button
          v-if="isAdmin && selectedRowKeys.length > 0"
          danger
          @click="handleBatchCancel"
          :loading="batchCanceling"
        >
          <template #icon>
            <StopOutlined />
          </template>
          批量取消 ({{ selectedRowKeys.length }})
        </a-button>
        <a-button
          v-if="isAdmin && selectedRowKeys.length > 0"
          @click="handleBatchDelete"
          :loading="batchDeleting"
        >
          <template #icon>
            <DeleteOutlined />
          </template>
          批量删除 ({{ selectedRowKeys.length }})
        </a-button>
        <a-button v-if="isAdmin" type="primary" @click="handleCreate">
          <template #icon>
            <PlusOutlined />
          </template>
          新建任务
        </a-button>
      </a-space>
    </div>

    <!-- 筛选条件 -->
    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-form layout="inline" :model="filters">
        <a-form-item label="任务类型">
          <a-select
            v-model:value="filters.type"
            placeholder="选择类型"
            style="width: 150px"
            allow-clear
          >
            <a-select-option value="baseline">基线检查</a-select-option>
            <a-select-option value="manual">手动任务</a-select-option>
            <a-select-option value="scheduled">定时任务</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="状态">
          <a-select
            v-model:value="filters.status"
            placeholder="选择状态"
            style="width: 150px"
            allow-clear
          >
            <a-select-option value="created">已创建</a-select-option>
            <a-select-option value="pending">待执行</a-select-option>
            <a-select-option value="running">执行中</a-select-option>
            <a-select-option value="completed">已完成</a-select-option>
            <a-select-option value="failed">失败</a-select-option>
            <a-select-option value="cancelled">已取消</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="任务名称">
          <a-input
            v-model:value="filters.name"
            placeholder="输入任务名称"
            style="width: 200px"
            allow-clear
          />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" @click="handleSearch">
            <template #icon>
              <SearchOutlined />
            </template>
            查询
          </a-button>
          <a-button style="margin-left: 8px" @click="handleReset">重置</a-button>
          <a-button style="margin-left: 8px" @click="handleRefresh" :loading="loading">
            <template #icon>
              <ReloadOutlined />
            </template>
            刷新
          </a-button>
        </a-form-item>
      </a-form>
    </a-card>

    <!-- 任务列表表格 -->
    <a-table
      :columns="columns"
      :data-source="tasks"
      :loading="loading"
      :pagination="pagination"
      :row-selection="rowSelection"
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
        <template v-else-if="column.key === 'type'">
          <a-tag :color="getTypeColor(record.type)">
            {{ getTypeText(record.type) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'target_type'">
          <a-tag>{{ getTargetTypeText(record.target_type) }}</a-tag>
        </template>
        <template v-else-if="column.key === 'policy_ids'">
          <template v-if="getTaskPolicyIds(record).length > 0">
            <a-tooltip v-if="getTaskPolicyIds(record).length > 1">
              <template #title>
                <div v-for="policyId in getTaskPolicyIds(record)" :key="policyId">
                  {{ policyId }}
                </div>
              </template>
              <span>
                <a-tag>{{ getTaskPolicyIds(record)[0] }}</a-tag>
                <span style="color: #3B82F6; cursor: pointer;">+{{ getTaskPolicyIds(record).length - 1 }}</span>
              </span>
            </a-tooltip>
            <a-tag v-else>{{ getTaskPolicyIds(record)[0] }}</a-tag>
          </template>
          <span v-else>-</span>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space size="small">
            <!-- 已创建或失败状态才能执行（仅管理员） -->
            <a-popconfirm
              v-if="isAdmin && (record.status === 'created' || record.status === 'failed')"
              title="确定要执行此任务吗？"
              ok-text="确定"
              cancel-text="取消"
              @confirm="handleRun(record)"
            >
              <a-button
                type="link"
                size="small"
                :loading="runningTasks[record.task_id]"
              >
                执行
              </a-button>
            </a-popconfirm>
            <!-- 已创建、待执行或执行中状态都可以取消（仅管理员） -->
            <a-popconfirm
              v-if="isAdmin && (record.status === 'created' || record.status === 'pending' || record.status === 'running')"
              title="确定要取消此任务吗？"
              ok-text="确定"
              cancel-text="取消"
              @confirm="handleCancel(record)"
            >
              <a-button
                type="link"
                size="small"
                danger
                :loading="cancelingTasks[record.task_id]"
              >
                取消
              </a-button>
            </a-popconfirm>
            <a-button type="link" size="small" @click="handleViewDetail(record)">
              查看
            </a-button>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 创建任务对话框 -->
    <TaskModal
      v-model:open="modalVisible"
      @success="handleModalSuccess"
    />

    <!-- 任务详情对话框 -->
    <a-modal
      v-model:open="detailModalVisible"
      title="任务详情"
      width="900px"
      :footer="null"
    >
      <template #title>
        <div class="modal-title-with-refresh">
          <span>任务详情</span>
          <a-button
            type="text"
            size="small"
            @click="handleRefreshDetail"
            :loading="detailRefreshing"
            class="refresh-detail-btn"
          >
            <template #icon>
              <ReloadOutlined />
            </template>
            刷新
          </a-button>
        </div>
      </template>
      <a-descriptions v-if="selectedTask" :column="2" bordered size="small" class="task-detail-descriptions">
        <a-descriptions-item label="任务ID" :span="2">
          <span style="font-family: monospace;">{{ selectedTask.task_id }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="任务名称">
          {{ selectedTask.name }}
        </a-descriptions-item>
        <a-descriptions-item label="任务类型">
          <a-tag :color="getTypeColor(selectedTask.type)">
            {{ getTypeText(selectedTask.type) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="状态">
          <a-tag :color="getStatusColor(selectedTask.status)">
            <template #icon v-if="selectedTask.status === 'running'">
              <SyncOutlined spin />
            </template>
            {{ getStatusText(selectedTask.status) }}
          </a-tag>
          <!-- 执行中显示取消按钮（仅管理员） -->
          <a-popconfirm
            v-if="isAdmin && selectedTask.status === 'running'"
            title="确定要取消此任务吗？"
            ok-text="确定"
            cancel-text="取消"
            @confirm="handleCancelFromDetail"
          >
            <a-button
              type="link"
              danger
              size="small"
              style="margin-left: 8px;"
              :loading="cancelingTasks[selectedTask.task_id]"
            >
              取消任务
            </a-button>
          </a-popconfirm>
        </a-descriptions-item>
        <a-descriptions-item label="目标类型">
          <a-tag>{{ getTargetTypeText(selectedTask.target_type) }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="关联策略" :span="2">
          <div class="policy-tags-wrapper">
            <template v-if="getTaskPolicyIds(selectedTask).length > 0">
              <a-tag v-for="policyId in getTaskPolicyIds(selectedTask)" :key="policyId">
                {{ policyId }}
              </a-tag>
              <span class="policy-count">
                (共 {{ getTaskPolicyIds(selectedTask).length }} 个策略<template v-if="selectedTask.total_rule_count">，{{ selectedTask.total_rule_count }} 条规则</template>)
              </span>
            </template>
            <span v-else>-</span>
          </div>
        </a-descriptions-item>
        <a-descriptions-item label="目标主机" :span="2">
          <template v-if="selectedTask.target_type === 'all'">
            <span>全部主机</span>
            <a-tag v-if="selectedTask.matched_host_count !== undefined" color="blue" style="margin-left: 8px;">
              在线: {{ selectedTask.matched_host_count }} / 总计: {{ selectedTask.total_host_count }}
            </a-tag>
          </template>
          <template v-else-if="selectedTask.target_hosts && selectedTask.target_hosts.length > 0">
            <a-tag v-for="host in selectedTask.target_hosts.slice(0, 5)" :key="host">
              {{ host }}
            </a-tag>
            <span v-if="selectedTask.target_hosts.length > 5">
              等 {{ selectedTask.target_hosts.length }} 台主机
            </span>
            <a-tag v-if="selectedTask.matched_host_count !== undefined" color="blue" style="margin-left: 8px;">
              在线: {{ selectedTask.matched_host_count }} / 总计: {{ selectedTask.total_host_count }}
            </a-tag>
          </template>
          <template v-else>
            <span>-</span>
          </template>
        </a-descriptions-item>
        <a-descriptions-item label="创建时间">
          {{ formatTime(selectedTask.created_at) }}
        </a-descriptions-item>
        <a-descriptions-item label="执行时间">
          {{ formatTime(selectedTask.executed_at) || '-' }}
        </a-descriptions-item>
        <a-descriptions-item label="完成时间" :span="2">
          {{ formatTime(selectedTask.completed_at) || '-' }}
        </a-descriptions-item>
      </a-descriptions>

      <!-- 执行进度（如果正在执行） -->
      <div v-if="selectedTask?.status === 'running'" class="task-progress">
        <a-divider>执行进度</a-divider>
        <a-progress
          :percent="taskProgress"
          :status="'active'"
          :format="(percent: number) => `${percent}%`"
          :stroke-color="{
            '0%': '#108ee9',
            '100%': '#87d068',
          }"
        />
        <div class="progress-info">
          <span>已完成: {{ taskResultStats.total }} / {{ selectedTask?.expected_check_count || 0 }} 项</span>
          <span>通过: {{ taskResultStats.pass }}</span>
          <span>失败: {{ taskResultStats.fail }}</span>
        </div>
        <p class="progress-tip">
          <SyncOutlined spin /> 任务正在执行中，请稍候...
        </p>
      </div>

      <!-- 主机执行状态 -->
      <div v-if="selectedTask && (selectedTask.status === 'running' || selectedTask.status === 'completed' || selectedTask.status === 'failed')" class="host-status-section">
        <a-divider>主机执行状态</a-divider>
        <a-table
          :columns="hostStatusColumns"
          :data-source="hostStatuses"
          :loading="hostStatusLoading"
          :pagination="false"
          size="small"
          row-key="id"
          :scroll="{ x: 'max-content' }"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'host_id'">
              <a-tooltip :title="record.host_id">
                <span
                  class="host-id-cell"
                  @click="handleCopyHostId(record.host_id)"
                >
                  {{ truncateHostId(record.host_id) }}
                  <CopyOutlined class="copy-icon" />
                </span>
              </a-tooltip>
            </template>
            <template v-else-if="column.key === 'status'">
              <a-tag :color="getHostStatusColor(record.status)">
                {{ getHostStatusText(record.status) }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'dispatched_at'">
              {{ formatTime(record.dispatched_at) }}
            </template>
            <template v-else-if="column.key === 'completed_at'">
              {{ formatTime(record.completed_at) || '-' }}
            </template>
            <template v-else-if="column.key === 'error_message'">
              <a-tooltip v-if="record.error_message" :title="record.error_message">
                <span class="error-message-text">{{ record.error_message.slice(0, 30) }}...</span>
              </a-tooltip>
              <span v-else>-</span>
            </template>
          </template>
        </a-table>
      </div>

      <!-- 执行结果统计（如果已完成） -->
      <div v-if="selectedTask?.status === 'completed' || selectedTask?.status === 'failed'" class="task-result">
        <a-divider>执行结果</a-divider>
        <a-row :gutter="16">
          <a-col :span="6">
            <a-statistic
              title="总计"
              :value="taskResultStats.total"
            >
              <template #prefix>
                <UnorderedListOutlined />
              </template>
            </a-statistic>
          </a-col>
          <a-col :span="6">
            <a-statistic
              title="通过"
              :value="taskResultStats.pass"
              :value-style="{ color: '#3f8600' }"
            >
              <template #prefix>
                <CheckCircleOutlined />
              </template>
            </a-statistic>
          </a-col>
          <a-col :span="6">
            <a-statistic
              title="失败"
              :value="taskResultStats.fail"
              :value-style="{ color: '#DC2626' }"
            >
              <template #prefix>
                <CloseCircleOutlined />
              </template>
            </a-statistic>
          </a-col>
          <a-col :span="6">
            <a-statistic
              title="错误"
              :value="taskResultStats.error"
              :value-style="{ color: '#F59E0B' }"
            >
              <template #prefix>
                <ExclamationCircleOutlined />
              </template>
            </a-statistic>
          </a-col>
        </a-row>

        <!-- 详细结果表格 -->
        <div class="detailed-results" style="margin-top: 16px;">
          <div class="result-filter" style="margin-bottom: 12px;">
            <span style="margin-right: 8px;">筛选:</span>
            <a-radio-group v-model:value="resultFilter" size="small">
              <a-radio-button value="all">全部 ({{ taskResultStats.total }})</a-radio-button>
              <a-radio-button value="fail">失败 ({{ taskResultStats.fail }})</a-radio-button>
              <a-radio-button value="error">错误 ({{ taskResultStats.error }})</a-radio-button>
              <a-radio-button value="pass">通过 ({{ taskResultStats.pass }})</a-radio-button>
            </a-radio-group>
          </div>
          <a-table
            :columns="detailedResultColumns"
            :data-source="filteredDetailedResults"
            :loading="detailResultsLoading"
            :pagination="detailPagination"
            @change="handleDetailTableChange"
            row-key="rule_id"
            size="small"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'status'">
                <a-tag :color="record.status === 'pass' ? 'green' : record.status === 'fail' ? 'red' : 'orange'">
                  {{ record.status === 'pass' ? '通过' : record.status === 'fail' ? '失败' : '错误' }}
                </a-tag>
              </template>
              <template v-else-if="column.key === 'failure_reason'">
                <template v-if="record.status === 'fail' || record.status === 'error'">
                  <a-tooltip v-if="record.actual || record.expected" placement="topLeft">
                    <template #title>
                      <div>
                        <div v-if="record.expected"><strong>期望值:</strong> {{ record.expected }}</div>
                        <div v-if="record.actual"><strong>实际值:</strong> {{ record.actual }}</div>
                      </div>
                    </template>
                    <span class="failure-reason">
                      {{ record.actual ? `实际: ${record.actual.slice(0, 50)}${record.actual.length > 50 ? '...' : ''}` : '检查失败' }}
                    </span>
                  </a-tooltip>
                  <span v-else class="failure-reason">检查失败</span>
                </template>
                <span v-else style="color: #999;">-</span>
              </template>
            </template>
          </a-table>
        </div>
      </div>

      <!-- 执行日志 -->
      <div class="task-logs">
        <a-divider>执行日志</a-divider>
        <a-spin :spinning="logsLoading">
          <div class="logs-container" ref="logsContainer">
            <div v-if="taskLogs.length === 0" class="no-logs">
              暂无执行日志
            </div>
            <div v-else class="log-list">
              <div
                v-for="(log, index) in taskLogs"
                :key="index"
                :class="['log-item', `log-${log.level}`]"
              >
                <span class="log-time">{{ log.time }}</span>
                <span class="log-level">{{ log.level.toUpperCase() }}</span>
                <span class="log-message">{{ log.message }}</span>
              </div>
            </div>
          </div>
        </a-spin>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, nextTick } from 'vue'
import { message, Modal } from 'ant-design-vue'
import {
  PlusOutlined,
  SearchOutlined,
  PlayCircleOutlined,
  SyncOutlined,
  StopOutlined,
  DeleteOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  UnorderedListOutlined,
  ReloadOutlined,
  CopyOutlined,
} from '@ant-design/icons-vue'
import { tasksApi } from '@/api/tasks'
import { resultsApi } from '@/api/results'
import { hostsApi } from '@/api/hosts'
import { useAuthStore } from '@/stores/auth'
import type { ScanTask } from '@/api/types'
import TaskModal from './components/TaskModal.vue'

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

interface TaskLog {
  time: string
  level: 'info' | 'success' | 'warning' | 'error'
  message: string
}

const loading = ref(false)
const tasks = ref<ScanTask[]>([])
const filters = reactive({
  status: undefined as string | undefined,
  type: undefined as string | undefined,
  name: undefined as string | undefined,
})
const modalVisible = ref(false)
const detailModalVisible = ref(false)
const selectedTask = ref<ScanTask | null>(null)
const runningTasks = reactive<Record<string, boolean>>({})
const cancelingTasks = reactive<Record<string, boolean>>({})
const taskProgress = ref(0)
const taskResultStats = reactive({
  total: 0,
  pass: 0,
  fail: 0,
  error: 0,
})
const taskLogs = ref<TaskLog[]>([])
const logsLoading = ref(false)
const logsContainer = ref<HTMLElement | null>(null)
const detailRefreshing = ref(false)

// 主机执行状态
interface HostStatus {
  id: number
  task_id: string
  host_id: string
  hostname: string
  status: 'dispatched' | 'completed' | 'timeout' | 'failed'
  dispatched_at: string
  completed_at?: string
  error_message?: string
  created_at: string
  updated_at: string
}
const hostStatuses = ref<HostStatus[]>([])
const hostStatusLoading = ref(false)
const hostStatusColumns = [
  {
    title: '主机ID',
    dataIndex: 'host_id',
    key: 'host_id',
    width: 180,
    ellipsis: true,
  },
  {
    title: '主机名',
    dataIndex: 'hostname',
    key: 'hostname',
    width: 150,
    ellipsis: true,
  },
  {
    title: '状态',
    dataIndex: 'status',
    key: 'status',
    width: 90,
    align: 'center' as const,
  },
  {
    title: '下发时间',
    dataIndex: 'dispatched_at',
    key: 'dispatched_at',
    width: 160,
  },
  {
    title: '完成时间',
    dataIndex: 'completed_at',
    key: 'completed_at',
    width: 160,
  },
  {
    title: '错误信息',
    dataIndex: 'error_message',
    key: 'error_message',
    ellipsis: true,
  },
]

// 任务详细结果
interface DetailedResult {
  host_id: string
  hostname: string
  rule_id: string
  title: string
  status: string
  actual?: string
  expected?: string
}
const detailedResults = ref<DetailedResult[]>([])
const detailResultsLoading = ref(false)
const resultFilter = ref<'all' | 'fail' | 'error' | 'pass'>('all')
const detailPagination = ref({
  pageSize: 20,
  showSizeChanger: true,
  pageSizeOptions: ['10', '20', '50', '100'],
  showTotal: (total: number) => `共 ${total} 条`
})

// 批量操作相关
const selectedRowKeys = ref<string[]>([])
const batchCanceling = ref(false)
const batchDeleting = ref(false)
const batchRunning = ref(false)

// 行选择配置
const rowSelection = computed(() => ({
  selectedRowKeys: selectedRowKeys.value,
  onChange: (keys: string[]) => {
    selectedRowKeys.value = keys
  },
  getCheckboxProps: (_record: ScanTask) => ({
    disabled: false,
  }),
}))

// 自动刷新定时器
let refreshTimer: ReturnType<typeof setInterval> | null = null
let detailRefreshTimer: ReturnType<typeof setInterval> | null = null

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: '任务名称',
    dataIndex: 'name',
    key: 'name',
    width: 200,
  },
  {
    title: '任务类型',
    dataIndex: 'type',
    key: 'type',
    width: 120,
  },
  {
    title: '目标类型',
    key: 'target_type',
    width: 120,
  },
  {
    title: '关联策略',
    key: 'policy_ids',
    width: 250,
  },
  {
    title: '状态',
    key: 'status',
    width: 120,
  },
  {
    title: '创建时间',
    dataIndex: 'created_at',
    key: 'created_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text),
  },
  {
    title: '执行时间',
    dataIndex: 'executed_at',
    key: 'executed_at',
    width: 180,
    customRender: ({ text }: { text: string }) => formatTime(text) || '-',
  },
  {
    title: '操作',
    key: 'action',
    width: 120,
    fixed: 'right' as const,
  },
]

// 详细结果表格列定义
const detailedResultColumns = [
  {
    title: '主机名',
    dataIndex: 'hostname',
    key: 'hostname',
    width: 180,
    ellipsis: true,
  },
  {
    title: '主机ID',
    dataIndex: 'host_id',
    key: 'host_id',
    width: 120,
    ellipsis: true,
    customRender: ({ text }: { text: string }) => text ? `${text.slice(0, 8)}...` : '-',
  },
  {
    title: '检查项',
    dataIndex: 'title',
    key: 'title',
    ellipsis: true,
  },
  {
    title: '结果',
    key: 'status',
    width: 80,
  },
  {
    title: '失败原因',
    key: 'failure_reason',
    width: 250,
    ellipsis: true,
  },
]

// 过滤后的详细结果
const filteredDetailedResults = computed(() => {
  if (resultFilter.value === 'all') {
    return detailedResults.value
  } else if (resultFilter.value === 'fail') {
    return detailedResults.value.filter(r => r.status === 'fail')
  } else if (resultFilter.value === 'error') {
    return detailedResults.value.filter(r => r.status === 'error')
  } else {
    return detailedResults.value.filter(r => r.status === 'pass')
  }
})

const loadTasks = async () => {
  loading.value = true
  try {
    const response = await tasksApi.list({
      page: pagination.current,
      page_size: pagination.pageSize,
      status: filters.status,
    }) as any
    tasks.value = response.items || []
    pagination.total = response.total || 0
  } catch (error) {
    console.error('加载任务列表失败:', error)
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  pagination.current = 1
  loadTasks()
}

const handleReset = () => {
  filters.status = undefined
  filters.type = undefined
  filters.name = undefined
  pagination.current = 1
  selectedRowKeys.value = []
  loadTasks()
}

const handleRefresh = () => {
  loadTasks()
  message.success('已刷新')
}

// 批量执行任务
const handleBatchRun = () => {
  const runnableTasks = tasks.value.filter(
    t => selectedRowKeys.value.includes(t.task_id) && (t.status === 'created' || t.status === 'pending')
  )

  if (runnableTasks.length === 0) {
    message.warning('没有可执行的任务（只有已创建或待执行状态的任务可以执行）')
    return
  }

  Modal.confirm({
    title: '批量执行任务',
    content: `确定要执行 ${runnableTasks.length} 个任务吗？`,
    okText: '确认执行',
    cancelText: '取消',
    async onOk() {
      batchRunning.value = true
      let successCount = 0
      let failCount = 0

      for (const task of runnableTasks) {
        try {
          await tasksApi.run(task.task_id)
          successCount++
        } catch (error) {
          console.error(`执行任务 ${task.task_id} 失败:`, error)
          failCount++
        }
      }

      batchRunning.value = false
      selectedRowKeys.value = []

      if (failCount === 0) {
        message.success(`成功执行 ${successCount} 个任务`)
      } else {
        message.warning(`成功执行 ${successCount} 个任务，${failCount} 个任务执行失败`)
      }

      loadTasks()
      // 开始自动刷新
      startAutoRefresh()
    },
  })
}

// 批量取消任务
const handleBatchCancel = () => {
  const cancelableTasks = tasks.value.filter(
    t => selectedRowKeys.value.includes(t.task_id) && (t.status === 'created' || t.status === 'pending' || t.status === 'running')
  )

  if (cancelableTasks.length === 0) {
    message.warning('没有可取消的任务（只有已创建、待执行或执行中的任务可以取消）')
    return
  }

  Modal.confirm({
    title: '批量取消任务',
    content: `确定要取消 ${cancelableTasks.length} 个任务吗？`,
    okText: '确认取消',
    okType: 'danger',
    cancelText: '取消',
    async onOk() {
      batchCanceling.value = true
      let successCount = 0
      let failCount = 0

      for (const task of cancelableTasks) {
        try {
          await tasksApi.cancel(task.task_id)
          successCount++
        } catch (error) {
          console.error(`取消任务 ${task.task_id} 失败:`, error)
          failCount++
        }
      }

      batchCanceling.value = false
      selectedRowKeys.value = []

      if (failCount === 0) {
        message.success(`成功取消 ${successCount} 个任务`)
      } else {
        message.warning(`成功取消 ${successCount} 个任务，${failCount} 个任务取消失败`)
      }

      loadTasks()
    },
  })
}

// 批量删除任务
const handleBatchDelete = () => {
  const deletableTasks = tasks.value.filter(
    t => selectedRowKeys.value.includes(t.task_id) && (t.status === 'created' || t.status === 'pending' || t.status === 'completed' || t.status === 'failed')
  )

  if (deletableTasks.length === 0) {
    message.warning('没有可删除的任务（执行中的任务不能删除）')
    return
  }

  Modal.confirm({
    title: '批量删除任务',
    content: `确定要删除 ${deletableTasks.length} 个任务吗？此操作不可恢复。`,
    okText: '确认删除',
    okType: 'danger',
    cancelText: '取消',
    async onOk() {
      batchDeleting.value = true
      let successCount = 0
      let failCount = 0

      for (const task of deletableTasks) {
        try {
          await tasksApi.delete(task.task_id)
          successCount++
        } catch (error) {
          console.error(`删除任务 ${task.task_id} 失败:`, error)
          failCount++
        }
      }

      batchDeleting.value = false
      selectedRowKeys.value = []

      if (failCount === 0) {
        message.success(`成功删除 ${successCount} 个任务`)
      } else {
        message.warning(`成功删除 ${successCount} 个任务，${failCount} 个任务删除失败`)
      }

      loadTasks()
    },
  })
}

const handleCreate = () => {
  modalVisible.value = true
}

const handleRun = async (record: ScanTask) => {
  runningTasks[record.task_id] = true
  try {
    await tasksApi.run(record.task_id)
    message.success('任务已开始执行')
    loadTasks()
    // 开始自动刷新
    startAutoRefresh()
  } catch (error) {
    console.error('执行任务失败:', error)
  } finally {
    runningTasks[record.task_id] = false
  }
}

const handleCancel = async (record: ScanTask) => {
  cancelingTasks[record.task_id] = true
  try {
    // 调用取消任务 API
    await tasksApi.cancel(record.task_id)
    message.success('任务已取消')
    loadTasks()
  } catch (error) {
    console.error('取消任务失败:', error)
  } finally {
    cancelingTasks[record.task_id] = false
  }
}

const handleCancelFromDetail = async () => {
  if (!selectedTask.value) return
  await handleCancel(selectedTask.value)
  // 重新加载详情
  if (selectedTask.value) {
    await refreshTaskDetail(selectedTask.value.task_id)
  }
}

const handleViewDetail = async (record: ScanTask) => {
  selectedTask.value = record
  detailModalVisible.value = true
  taskProgress.value = 0
  taskResultStats.total = 0
  taskResultStats.pass = 0
  taskResultStats.fail = 0
  taskResultStats.error = 0
  taskLogs.value = []
  hostStatuses.value = []

  // 加载任务结果统计
  await loadTaskResultStats(record.task_id)

  // 加载主机执行状态
  await loadHostStatus(record.task_id)

  // 生成执行日志
  generateTaskLogs(record)

  // 如果任务正在执行，启动定时刷新
  if (record.status === 'running') {
    startDetailRefresh(record.task_id)
  }
}

const refreshTaskDetail = async (taskId: string) => {
  try {
    const task = await tasksApi.get(taskId) as any
    selectedTask.value = task
    await loadTaskResultStats(taskId)
    await loadHostStatus(taskId)
    generateTaskLogs(task)

    // 如果任务已完成，停止刷新
    if (task.status !== 'running') {
      stopDetailRefresh()
    }
  } catch (error) {
    console.error('刷新任务详情失败:', error)
  }
}

// 加载主机执行状态
const loadHostStatus = async (taskId: string) => {
  hostStatusLoading.value = true
  try {
    const response = await tasksApi.getHostStatus(taskId) as any
    hostStatuses.value = response.hosts || []
  } catch (error) {
    console.error('获取主机执行状态失败:', error)
  } finally {
    hostStatusLoading.value = false
  }
}

// 获取主机状态颜色
const getHostStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    dispatched: 'blue',
    completed: 'green',
    timeout: 'orange',
    failed: 'red',
  }
  return colors[status] || 'default'
}

// 获取主机状态文本
const getHostStatusText = (status: string) => {
  const texts: Record<string, string> = {
    dispatched: '已下发',
    completed: '已完成',
    timeout: '超时',
    failed: '失败',
  }
  return texts[status] || status
}

// 截断主机ID显示
const truncateHostId = (hostId: string) => {
  if (!hostId) return '-'
  if (hostId.length <= 16) return hostId
  return hostId.slice(0, 8) + '...' + hostId.slice(-6)
}

// 复制主机ID
const handleCopyHostId = async (hostId: string) => {
  try {
    await navigator.clipboard.writeText(hostId)
    message.success('已复制主机ID')
  } catch (err) {
    message.error('复制失败')
  }
}

const loadTaskResultStats = async (taskId: string) => {
  detailResultsLoading.value = true
  try {
    // 先获取总数
    const firstResponse = await resultsApi.list({
      task_id: taskId,
      page: 1,
      page_size: 1,
    }) as any
    const totalCount = firstResponse.total || 0

    // 如果有结果，获取所有数据
    let results: any[] = []
    if (totalCount > 0) {
      const fullResponse = await resultsApi.list({
        task_id: taskId,
        page: 1,
        page_size: totalCount,
      }) as any
      results = fullResponse.items || []
    }

    taskResultStats.total = results.length
    taskResultStats.pass = results.filter((r: any) => r.status === 'pass').length
    taskResultStats.fail = results.filter((r: any) => r.status === 'fail').length
    taskResultStats.error = results.filter((r: any) => r.status === 'error').length

    // 获取主机名映射
    const hostIds = [...new Set(results.map((r: any) => r.host_id))]
    let hostsMap = new Map<string, string>()
    if (hostIds.length > 0) {
      try {
        const hostsResponse = await hostsApi.list({ page_size: 1000 }) as any
        const hosts = hostsResponse.items || []
        hosts.forEach((h: any) => {
          hostsMap.set(h.host_id, h.hostname)
        })
      } catch (e) {
        console.error('获取主机列表失败:', e)
      }
    }

    // 构建详细结果列表
    detailedResults.value = results.map((r: any) => ({
      host_id: r.host_id,
      hostname: hostsMap.get(r.host_id) || r.host_id,
      rule_id: r.rule_id,
      title: r.title || r.rule_id,
      status: r.status,
      actual: r.actual,
      expected: r.expected,
    }))

    // 计算进度百分比（基于预期检查项数量）
    const expectedTotal = selectedTask.value?.expected_check_count || 0
    if (expectedTotal > 0) {
      const completedPercent = Math.round((taskResultStats.total / expectedTotal) * 100)
      if (selectedTask.value?.status === 'running') {
        // 执行中时最大显示 99%
        taskProgress.value = Math.min(completedPercent, 99)
      } else {
        // 已完成/失败等状态，显示真实进度（可能不到 100%）
        taskProgress.value = Math.min(completedPercent, 100)
      }
    } else if (selectedTask.value?.status === 'completed') {
      taskProgress.value = 100
    } else {
      taskProgress.value = 0
    }
  } catch (error) {
    console.error('加载任务结果统计失败:', error)
  } finally {
    detailResultsLoading.value = false
  }
}

const generateTaskLogs = (task: ScanTask) => {
  const logs: TaskLog[] = []

  // 创建时间日志
  if (task.created_at) {
    logs.push({
      time: formatLogTime(task.created_at),
      level: 'info',
      message: `任务创建成功，任务ID: ${task.task_id}`,
    })
  }

  // 执行时间日志
  if (task.executed_at) {
    logs.push({
      time: formatLogTime(task.executed_at),
      level: 'info',
      message: '任务开始执行',
    })
    // 使用新的字段显示主机数量
    let targetHostMessage = ''
    if (task.target_type === 'all') {
      targetHostMessage = `全部主机 (在线: ${task.matched_host_count ?? 0} / 总计: ${task.total_host_count ?? 0})`
    } else {
      targetHostMessage = `${task.total_host_count ?? task.target_hosts?.length ?? 0} 台主机 (在线: ${task.matched_host_count ?? 0})`
    }
    logs.push({
      time: formatLogTime(task.executed_at),
      level: 'info',
      message: `目标主机: ${targetHostMessage}`,
    })
    const policyIds = getTaskPolicyIds(task)
    logs.push({
      time: formatLogTime(task.executed_at),
      level: 'info',
      message: `关联策略: ${policyIds.length > 0 ? policyIds.join(', ') : '无'}${policyIds.length > 1 ? ` (共 ${policyIds.length} 个)` : ''}`,
    })
  }

  // 根据当前状态添加日志
  if (task.status === 'running') {
    if (taskResultStats.total > 0) {
      logs.push({
        time: formatLogTime(new Date().toISOString()),
        level: 'info',
        message: `正在执行检查... 已完成 ${taskResultStats.total} 项`,
      })
      if (taskResultStats.pass > 0) {
        logs.push({
          time: formatLogTime(new Date().toISOString()),
          level: 'success',
          message: `${taskResultStats.pass} 项检查通过`,
        })
      }
      if (taskResultStats.fail > 0) {
        logs.push({
          time: formatLogTime(new Date().toISOString()),
          level: 'warning',
          message: `${taskResultStats.fail} 项检查失败`,
        })
      }
    }
  }

  // 完成时间日志
  if (task.completed_at) {
    if (task.status === 'completed') {
      logs.push({
        time: formatLogTime(task.completed_at),
        level: 'success',
        message: `任务执行完成，共检查 ${taskResultStats.total} 项`,
      })
      logs.push({
        time: formatLogTime(task.completed_at),
        level: taskResultStats.fail > 0 ? 'warning' : 'success',
        message: `结果统计: 通过 ${taskResultStats.pass} 项, 失败 ${taskResultStats.fail} 项, 错误 ${taskResultStats.error} 项`,
      })
    } else if (task.status === 'failed') {
      logs.push({
        time: formatLogTime(task.completed_at),
        level: 'error',
        message: '任务执行失败',
      })
    }
  }

  taskLogs.value = logs

  // 滚动到底部
  nextTick(() => {
    if (logsContainer.value) {
      logsContainer.value.scrollTop = logsContainer.value.scrollHeight
    }
  })
}

const formatLogTime = (time: string) => {
  // 如果是 YYYY-MM-DD HH:mm:ss 格式，先转换为 ISO 格式
  let date = new Date(time)
  if (isNaN(date.getTime()) && time.includes(' ')) {
    date = new Date(time.replace(' ', 'T'))
  }
  if (isNaN(date.getTime())) return time
  return date.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const handleRefreshDetail = async () => {
  if (!selectedTask.value) return
  detailRefreshing.value = true
  try {
    await refreshTaskDetail(selectedTask.value.task_id)
    message.success('已刷新')
  } finally {
    detailRefreshing.value = false
  }
}

const handleModalSuccess = () => {
  modalVisible.value = false
  loadTasks()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadTasks()
}

const handleDetailTableChange = (pag: any) => {
  detailPagination.value.pageSize = pag.pageSize
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = {
    created: 'default',
    pending: 'processing',
    running: 'processing',
    completed: 'success',
    failed: 'error',
    cancelled: 'warning',
  }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = {
    created: '已创建',
    pending: '待执行',
    running: '执行中',
    completed: '已完成',
    failed: '失败',
    cancelled: '已取消',
  }
  return texts[status] || status
}

const getTypeColor = (type: string) => {
  const colors: Record<string, string> = {
    baseline: 'blue',
    manual: 'green',
    scheduled: 'orange',
  }
  return colors[type] || 'default'
}

const getTypeText = (type: string) => {
  const texts: Record<string, string> = {
    baseline: '基线检查',
    manual: '手动任务',
    scheduled: '定时任务',
  }
  return texts[type] || type
}

const getTargetTypeText = (type: string) => {
  const texts: Record<string, string> = {
    all: '全部主机',
    host_ids: '指定主机',
    os_family: '按OS筛选',
  }
  return texts[type] || type
}

// 获取任务的策略ID列表（兼容新旧数据）
const getTaskPolicyIds = (task: ScanTask): string[] => {
  if (task.policy_ids && task.policy_ids.length > 0) {
    return task.policy_ids
  }
  if (task.policy_id) {
    return [task.policy_id]
  }
  return []
}

const formatTime = (time: string | undefined) => {
  if (!time) return ''
  // 如果是 YYYY-MM-DD HH:mm:ss 格式，先转换为 ISO 格式
  let date = new Date(time)
  if (isNaN(date.getTime()) && time.includes(' ')) {
    date = new Date(time.replace(' ', 'T'))
  }
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

// 自动刷新列表（当有任务执行中时）
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

// 详情页定时刷新
const startDetailRefresh = (taskId: string) => {
  if (detailRefreshTimer) return
  detailRefreshTimer = setInterval(() => {
    if (detailModalVisible.value && selectedTask.value?.status === 'running') {
      refreshTaskDetail(taskId)
    } else {
      stopDetailRefresh()
    }
  }, 3000)
}

const stopDetailRefresh = () => {
  if (detailRefreshTimer) {
    clearInterval(detailRefreshTimer)
    detailRefreshTimer = null
  }
}

onMounted(() => {
  loadTasks()
})

onUnmounted(() => {
  stopAutoRefresh()
  stopDetailRefresh()
})
</script>

<style scoped>
.tasks-page {
  width: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.task-progress {
  margin-top: 16px;
}

.progress-info {
  display: flex;
  justify-content: space-between;
  margin-top: 8px;
  color: #666;
  font-size: 13px;
}

.progress-tip {
  text-align: center;
  color: var(--mxsec-primary);
  margin-top: 8px;
}

.task-result {
  margin-top: 16px;
}

.task-logs {
  margin-top: 16px;
}

.logs-container {
  background: #1e1e1e;
  border-radius: 4px;
  padding: 12px;
  max-height: 300px;
  overflow-y: auto;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
}

.no-logs {
  color: #666;
  text-align: center;
  padding: 20px;
}

.log-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.log-item {
  display: flex;
  gap: 8px;
  line-height: 1.5;
}

.log-time {
  color: #888;
  min-width: 120px;
}

.log-level {
  min-width: 60px;
  font-weight: bold;
}

.log-message {
  flex: 1;
  word-break: break-all;
}

.log-info .log-level {
  color: var(--mxsec-primary);
}

.log-info .log-message {
  color: #d4d4d4;
}

.log-success .log-level {
  color: #22C55E;
}

.log-success .log-message {
  color: #22C55E;
}

.log-warning .log-level {
  color: #F59E0B;
}

.log-warning .log-message {
  color: #F59E0B;
}

.log-error .log-level {
  color: #EF4444;
}

.log-error .log-message {
  color: #EF4444;
}

/* 失败原因样式 */
.failure-reason {
  color: #EF4444;
  font-size: 12px;
  cursor: help;
}

.modal-title-with-refresh {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding-right: 40px;
}

.refresh-detail-btn {
  margin-left: auto;
}

/* 任务详情表格紧凑样式 */
.task-detail-descriptions :deep(.ant-descriptions-item-label),
.task-detail-descriptions :deep(.ant-descriptions-item-content) {
  padding: 8px 12px !important;
}

.task-detail-descriptions :deep(.ant-descriptions-item-label) {
  width: 80px;
  min-width: 80px;
}

/* 策略标签容器 */
.policy-tags-wrapper {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.policy-tags-wrapper .ant-tag {
  margin: 0;
}

.policy-count {
  color: #666;
  font-size: 12px;
  margin-left: 4px;
}

/* 主机执行状态表格样式 */
.host-status-section {
  margin-top: 16px;
}

.host-id-cell {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 12px;
  color: var(--mxsec-primary);
  padding: 2px 6px;
  border-radius: 4px;
  transition: all 0.2s;
}

.host-id-cell:hover {
  background-color: var(--mxsec-primary-bg);
}

.host-id-cell .copy-icon {
  font-size: 12px;
  opacity: 0;
  transition: opacity 0.2s;
}

.host-id-cell:hover .copy-icon {
  opacity: 1;
}

.error-message-text {
  color: #EF4444;
  font-size: 12px;
  cursor: help;
}
</style>
