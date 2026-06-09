<template>
  <div class="baseline-fix-page">
    <div class="page-header">
      <h2>基线修复</h2>
      <a-space>
        <a-button
          v-if="isAdmin && (selectedRowKeys.length > 0 || selectAllFiltered)"
          type="primary"
          @click="handleBatchFix"
          :loading="fixing"
        >
          <template #icon>
            <ToolOutlined />
          </template>
          <span v-if="selectAllFiltered">批量修复 (全部 {{ pagination.total }} 条)</span>
          <span v-else>批量修复 ({{ selectedRowKeys.length }})</span>
        </a-button>
        <a-button @click="handleRefresh" :loading="loading">
          <template #icon>
            <ReloadOutlined />
          </template>
          刷新
        </a-button>
      </a-space>
    </div>

    <!-- 全选提示 -->
    <a-alert
      v-if="showSelectAllAlert"
      type="info"
      closable
      @close="handleCloseSelectAllAlert"
      style="margin-bottom: 16px"
    >
      <template #message>
        <span>
          已选择当前页 {{ selectedRowKeys.length }} 条记录。
          <a @click="handleSelectAllFiltered" style="margin-left: 8px">
            选择全部 {{ pagination.total }} 条筛选结果
          </a>
        </span>
      </template>
    </a-alert>

    <!-- 全选所有筛选结果提示 -->
    <a-alert
      v-if="selectAllFiltered"
      type="success"
      closable
      @close="handleCancelSelectAll"
      style="margin-bottom: 16px"
    >
      <template #message>
        <span>
          已选择全部 {{ pagination.total }} 条筛选结果。
          <a @click="handleCancelSelectAll" style="margin-left: 8px">
            取消全选
          </a>
        </span>
      </template>
    </a-alert>

    <!-- 筛选条件 -->
    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-form layout="inline" :model="filters">
        <a-form-item label="业务线">
          <a-select
            v-model:value="filters.business_line"
            placeholder="选择业务线"
            style="width: 200px"
            allow-clear
            @change="handleBusinessLineChange"
          >
            <a-select-option v-for="line in businessLines" :key="line" :value="line">
              {{ line }}
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="主机选择">
          <a-select
            v-model:value="filters.host_ids"
            mode="multiple"
            placeholder="选择主机"
            style="width: 300px"
            allow-clear
            show-search
            :filter-option="filterHostOption"
            @change="handleFilterChange"
          >
            <a-select-option v-for="host in filteredHosts" :key="host.host_id" :value="host.host_id">
              {{ host.hostname }} ({{ host.ipv4[0] || host.host_id }})
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="风险等级">
          <a-checkbox-group v-model:value="filters.severities" @change="handleFilterChange">
            <a-checkbox value="critical">严重</a-checkbox>
            <a-checkbox value="high">高危</a-checkbox>
            <a-checkbox value="medium">中危</a-checkbox>
            <a-checkbox value="low">低危</a-checkbox>
          </a-checkbox-group>
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

    <!-- 统计信息 (统一 StatCard) -->
    <a-row :gutter="16" style="margin-bottom: 16px" v-if="fixableItems.length > 0">
      <a-col :span="6"><StatCard title="可修复项总数" :value="fixableItems.length" color="#3B82F6" /></a-col>
      <a-col :span="6"><StatCard title="严重" :value="fixableItems.filter(i => i.severity === 'critical').length" color="#DC2626" /></a-col>
      <a-col :span="6"><StatCard title="高危" :value="fixableItems.filter(i => i.severity === 'high').length" color="#F59E0B" /></a-col>
      <a-col :span="6"><StatCard title="有自动修复方案" :value="fixableItems.filter(i => i.has_fix).length" color="#22C55E" /></a-col>
    </a-row>

    <!-- 可修复项列表 -->
    <a-table
      :columns="columns"
      :data-source="fixableItems"
      :loading="loading"
      :pagination="pagination"
      :row-selection="rowSelection"
      @change="handleTableChange"
      :row-key="getRowKey"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'hostname'">
          <a @click="handleViewHost(record.host_id)">
            {{ record.hostname }}{{ record.ip ? ' (' + record.ip + ')' : '' }}
          </a>
        </template>
        <template v-else-if="column.key === 'business_line'">
          <a-tag v-if="record.business_line" color="blue">
            {{ record.business_line }}
          </a-tag>
          <span v-else style="color: #999">-</span>
        </template>
        <template v-else-if="column.key === 'severity'">
          <a-tag :color="getSeverityColor(record.severity)">
            {{ getSeverityText(record.severity) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'has_fix'">
          <a-tag v-if="record.has_fix" color="green">
            <CheckCircleOutlined /> 可自动修复
          </a-tag>
          <a-tag v-else color="default">
            <InfoCircleOutlined /> 需手动修复
          </a-tag>
        </template>
        <template v-else-if="column.key === 'action'">
          <a-space size="small">
            <a-button
              type="link"
              size="small"
              @click="handleViewDetail(record)"
            >
              查看详情
            </a-button>
            <a-popconfirm
              v-if="isAdmin && record.has_fix"
              title="确定要修复此项吗？"
              ok-text="确定"
              cancel-text="取消"
              @confirm="handleSingleFix(record)"
            >
              <a-button
                type="link"
                size="small"
                :loading="fixingItems[getRowKey(record)]"
              >
                立即修复
              </a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 详情 Modal -->
    <a-modal
      v-model:open="detailModalVisible"
      title="修复项详情"
      width="800px"
      :footer="null"
    >
      <a-descriptions v-if="selectedItem" :column="2" bordered size="small">
        <a-descriptions-item label="主机名" :span="2">
          {{ selectedItem.hostname }}
        </a-descriptions-item>
        <a-descriptions-item label="规则ID">
          {{ selectedItem.rule_id }}
        </a-descriptions-item>
        <a-descriptions-item label="类别">
          {{ selectedItem.category }}
        </a-descriptions-item>
        <a-descriptions-item label="标题" :span="2">
          {{ selectedItem.title }}
        </a-descriptions-item>
        <a-descriptions-item label="严重级别">
          <a-tag :color="getSeverityColor(selectedItem.severity)">
            {{ getSeverityText(selectedItem.severity) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="修复状态">
          <a-tag v-if="selectedItem.has_fix" color="green">
            可自动修复
          </a-tag>
          <a-tag v-else color="default">
            需手动修复
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="期望值" :span="2" v-if="selectedItem.expected">
          <code>{{ selectedItem.expected }}</code>
        </a-descriptions-item>
        <a-descriptions-item label="实际值" :span="2" v-if="selectedItem.actual">
          <code style="color: #EF4444;">{{ selectedItem.actual }}</code>
        </a-descriptions-item>
        <a-descriptions-item label="修复建议" :span="2" v-if="selectedItem.fix_suggestion">
          {{ selectedItem.fix_suggestion }}
        </a-descriptions-item>
        <a-descriptions-item label="修复命令" :span="2" v-if="selectedItem.fix_command">
          <div class="command-box">
            <code>{{ selectedItem.fix_command }}</code>
            <a-button
              type="link"
              size="small"
              @click="copyCommand(selectedItem.fix_command)"
            >
              <CopyOutlined /> 复制
            </a-button>
          </div>
        </a-descriptions-item>
      </a-descriptions>
      <div style="margin-top: 16px; text-align: right;" v-if="isAdmin && selectedItem?.has_fix">
        <a-popconfirm
          title="确定要执行修复吗？"
          ok-text="确定"
          cancel-text="取消"
          @confirm="handleSingleFix(selectedItem)"
        >
          <a-button type="primary" :loading="fixingItems[getRowKey(selectedItem)]">
            <ToolOutlined /> 执行修复
          </a-button>
        </a-popconfirm>
      </div>
    </a-modal>

    <!-- 修复进度 Modal -->
    <a-modal
      v-model:open="progressModalVisible"
      title="修复进度"
      width="700px"
      :closable="!fixing"
      :maskClosable="false"
      :footer="null"
    >
      <div class="fix-progress">
        <a-progress
          :percent="fixProgress"
          :status="fixing ? 'active' : fixSuccess ? 'success' : 'exception'"
        />
        <div class="progress-info">
          <span>总计: {{ fixTotal }}</span>
          <span>成功: {{ fixSuccessCount }}</span>
          <span>失败: {{ fixFailedCount }}</span>
        </div>

        <!-- 实时日志面板 -->
        <div class="live-log-panel" ref="logPanelRef">
          <div
            v-for="(log, index) in fixLogs"
            :key="index"
            :class="['live-log-line', `log-level-${log.level}`]"
          >
            <span class="log-time">{{ log.time }}</span>
            <span class="log-text">{{ log.text }}</span>
          </div>
          <div v-if="fixing" class="live-log-line log-level-info log-cursor">
            <span class="log-time">
              <SyncOutlined spin />
            </span>
            <span class="log-text">等待中...</span>
          </div>
        </div>
      </div>
      <div style="margin-top: 16px; text-align: right;" v-if="!fixing">
        <a-button type="primary" @click="handleCloseProgress">
          关闭
        </a-button>
      </div>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch, nextTick } from 'vue'
import { message } from 'ant-design-vue'
import { useRouter } from 'vue-router'
import {
  ToolOutlined,
  ReloadOutlined,
  SearchOutlined,
  UnorderedListOutlined,
  ExclamationCircleOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  CopyOutlined,
  SyncOutlined,
} from '@ant-design/icons-vue'
import { fixApi } from '@/api/fix'
import StatCard from '@/components/StatCard.vue'
import { hostsApi } from '@/api/hosts'
import { useAuthStore } from '@/stores/auth'
import type { FixableItem, Host, FixResult, FixTaskHostStatus } from '@/api/types'

const router = useRouter()
const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')

const loading = ref(false)
const fixing = ref(false)
const hosts = ref<Host[]>([])
const businessLines = ref<string[]>([])
const fixableItems = ref<FixableItem[]>([])
const selectedRowKeys = ref<string[]>([])
const detailModalVisible = ref(false)
const progressModalVisible = ref(false)
const selectedItem = ref<FixableItem | null>(null)
const fixingItems = reactive<Record<string, boolean>>({})

// 组合行键：用 task_id + host_id + rule_id 生成唯一标识
const getRowKey = (record: FixableItem) => `${record.task_id}_${record.host_id}_${record.rule_id}`

// 全选相关
const selectAllFiltered = ref(false) // 是否选择了所有筛选结果
const showSelectAllAlert = computed(() => {
  // 当选择了当前页的所有可修复项，且总数大于当前页数量时，显示提示
  if (selectAllFiltered.value) return false
  if (selectedRowKeys.value.length === 0) return false

  const fixableCount = fixableItems.value.filter(item => item.has_fix).length
  return selectedRowKeys.value.length === fixableCount && pagination.total > fixableCount
})

// 修复进度相关
const fixProgress = ref(0)
const fixTotal = ref(0)
const fixSuccessCount = ref(0)
const fixFailedCount = ref(0)
const fixSuccess = ref(false)
const fixResults = ref<FixResult[]>([])
const fixHostStatuses = ref<FixTaskHostStatus[]>([])

// 实时日志面板
const logPanelRef = ref<HTMLElement | null>(null)

interface LogEntry {
  time: string
  level: 'info' | 'success' | 'error' | 'warn' | 'cmd'
  text: string
}
const fixLogs = ref<LogEntry[]>([])
const appendLog = (level: LogEntry['level'], text: string) => {
  const now = new Date()
  const time = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
  fixLogs.value.push({ time, level, text })
}

// 日志自动滚到底部
watch(() => fixLogs.value.length, () => {
  nextTick(() => {
    if (logPanelRef.value) {
      logPanelRef.value.scrollTop = logPanelRef.value.scrollHeight
    }
  })
})

const filters = reactive({
  host_ids: [] as string[],
  business_line: '' as string,
  severities: ['critical', 'high'] as string[],
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  {
    title: '主机',
    dataIndex: 'hostname',
    key: 'hostname',
    width: 250,
    customRender: ({ record }: { record: FixableItem }) => {
      return `${record.hostname}${record.ip ? ' (' + record.ip + ')' : ''}`
    },
  },
  {
    title: '业务线',
    dataIndex: 'business_line',
    key: 'business_line',
    width: 120,
  },
  {
    title: '规则ID',
    dataIndex: 'rule_id',
    key: 'rule_id',
    width: 180,
    ellipsis: true,
  },
  {
    title: '类别',
    dataIndex: 'category',
    key: 'category',
    width: 100,
  },
  {
    title: '标题',
    dataIndex: 'title',
    key: 'title',
    ellipsis: true,
  },
  {
    title: '严重级别',
    key: 'severity',
    width: 100,
  },
  {
    title: '修复状态',
    key: 'has_fix',
    width: 130,
  },
  {
    title: '操作',
    key: 'action',
    width: 180,
    fixed: 'right' as const,
  },
]

const rowSelection = computed(() => ({
  selectedRowKeys: selectedRowKeys.value,
  onChange: (keys: string[]) => {
    selectedRowKeys.value = keys
  },
  getCheckboxProps: (record: FixableItem) => ({
    disabled: !record.has_fix,
  }),
}))

// 根据业务线筛选主机列表
const filteredHosts = computed(() => {
  if (!filters.business_line) {
    return hosts.value
  }
  return hosts.value.filter(host => host.business_line === filters.business_line)
})

const loadHosts = async () => {
  try {
    const response = await hostsApi.list({ page_size: 1000 }) as any
    hosts.value = response.items || []

    // 提取业务线列表（去重）
    const lines = new Set<string>()
    hosts.value.forEach(host => {
      if (host.business_line) {
        lines.add(host.business_line)
      }
    })
    businessLines.value = Array.from(lines).sort()
  } catch (error) {
    console.error('加载主机列表失败:', error)
  }
}

const loadFixableItems = async () => {
  loading.value = true
  try {
    const response = await fixApi.getFixableItems({
      host_ids: filters.host_ids.length > 0 ? filters.host_ids : undefined,
      business_line: filters.business_line || undefined,
      severities: filters.severities.length > 0 ? filters.severities : undefined,
      page: pagination.current,
      page_size: pagination.pageSize,
    })
    fixableItems.value = response.items || []
    pagination.total = response.total || 0
  } catch (error) {
    console.error('加载可修复项失败:', error)
    message.error('加载可修复项失败')
  } finally {
    loading.value = false
  }
}

const handleFilterChange = () => {
  // 筛选条件变化时不自动查询，等待用户点击查询按钮
}

const handleBusinessLineChange = () => {
  // 业务线变化时，清空主机选择（因为筛选后的主机列表可能不包含之前选择的主机）
  filters.host_ids = []
  handleFilterChange()
}

const handleSearch = () => {
  pagination.current = 1
  loadFixableItems()
}

const handleReset = () => {
  filters.host_ids = []
  filters.business_line = ''
  filters.severities = ['critical', 'high']
  pagination.current = 1
  selectedRowKeys.value = []
  loadFixableItems()
}

const handleRefresh = () => {
  loadFixableItems()
  message.success('已刷新')
}

// 全选所有筛选结果
const handleSelectAllFiltered = () => {
  selectAllFiltered.value = true
  // 清空当前页选择（因为我们要使用筛选条件而非具体ID）
  selectedRowKeys.value = []
}

// 取消全选所有筛选结果
const handleCancelSelectAll = () => {
  selectAllFiltered.value = false
  selectedRowKeys.value = []
}

// 关闭全选提示
const handleCloseSelectAllAlert = () => {
  // 用户关闭提示后，保持当前页选择状态
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  // 切换页面时，如果是全选状态，保持全选
  if (!selectAllFiltered.value) {
    selectedRowKeys.value = []
  }
  loadFixableItems()
}

const handleViewHost = (hostId: string) => {
  router.push(`/hosts/${hostId}`)
}

const handleViewDetail = (record: FixableItem) => {
  selectedItem.value = record
  detailModalVisible.value = true
}

const handleSingleFix = async (record: FixableItem) => {
  const key = getRowKey(record)
  fixingItems[key] = true
  try {
    const response = await fixApi.createFixTask({
      result_keys: [{ task_id: record.task_id, host_id: record.host_id, rule_id: record.rule_id }],
    })

    // 先关闭详情 Modal，再显示进度 Modal（避免详情 Modal 遮挡进度条）
    detailModalVisible.value = false

    // 显示进度 Modal
    progressModalVisible.value = true
    fixing.value = true
    fixProgress.value = 0
    // 单个修复：1 项
    fixTotal.value = 1
    fixSuccessCount.value = 0
    fixFailedCount.value = 0
    fixResults.value = []
    fixHostStatuses.value = []
    fixLogs.value = []
    appendLog('info', `修复任务已创建，待修复 1 项，等待调度...`)

    // 轮询任务状态
    const status = await pollFixTask(response.task_id)

    if (status === 'completed' && fixFailedCount.value === 0) {
      message.success('修复完成')
    } else if (status === 'completed') {
      message.warning(`修复完成，${fixSuccessCount.value} 项成功，${fixFailedCount.value} 项失败`)
    } else if (status === 'failed') {
      message.error('修复任务失败，请检查主机是否在线')
    }
    loadFixableItems()
  } catch (error: any) {
    console.error('修复失败:', error)
    message.error('修复失败: ' + (error.response?.data?.message || error.message))
  } finally {
    fixingItems[key] = false
  }
}

const handleBatchFix = async () => {
  // 如果选择了所有筛选结果
  if (selectAllFiltered.value) {
    fixing.value = true
    try {
      const response = await fixApi.createFixTask({
        use_filters: true,
        business_line: filters.business_line || undefined,
        severities: filters.severities.length > 0 ? filters.severities : undefined,
      })

      // 显示进度 Modal
      progressModalVisible.value = true
      fixProgress.value = 0
      // 使用总数作为预期修复数量
      fixTotal.value = pagination.total
      fixSuccessCount.value = 0
      fixFailedCount.value = 0
      fixResults.value = []
      fixHostStatuses.value = []
      fixLogs.value = []
      appendLog('info', `批量修复任务已创建，待修复 ${pagination.total} 项，等待调度...`)

      // 轮询任务状态
      const status = await pollFixTask(response.task_id)

      if (status === 'completed' && fixFailedCount.value === 0) {
        message.success('批量修复完成')
      } else if (status === 'completed') {
        message.warning(`批量修复完成，${fixSuccessCount.value} 项成功，${fixFailedCount.value} 项失败`)
      } else if (status === 'failed') {
        message.error('修复任务失败，请检查主机是否在线')
      }
      selectAllFiltered.value = false
      selectedRowKeys.value = []
      loadFixableItems()
    } catch (error: any) {
      console.error('批量修复失败:', error)
      message.error('批量修复失败: ' + (error.response?.data?.message || error.message))
    } finally {
      fixing.value = false
    }
    return
  }

  // 否则使用选中的具体项
  const selectedItems = fixableItems.value.filter(item =>
    selectedRowKeys.value.includes(getRowKey(item)) && item.has_fix
  )

  if (selectedItems.length === 0) {
    message.warning('请选择可自动修复的项')
    return
  }

  fixing.value = true
  try {
    const response = await fixApi.createFixTask({
      result_keys: selectedItems.map(item => ({ task_id: item.task_id, host_id: item.host_id, rule_id: item.rule_id })),
    })

    // 显示进度 Modal
    progressModalVisible.value = true
    fixProgress.value = 0
    // 使用选中的可修复项数量作为总数
    fixTotal.value = selectedItems.length
    fixSuccessCount.value = 0
    fixFailedCount.value = 0
    fixResults.value = []
    fixHostStatuses.value = []
    fixLogs.value = []
    appendLog('info', `批量修复任务已创建，待修复 ${selectedItems.length} 项，等待调度...`)

    // 轮询任务状态
    const status = await pollFixTask(response.task_id)

    if (status === 'completed' && fixFailedCount.value === 0) {
      message.success('批量修复完成')
    } else if (status === 'completed') {
      message.warning(`批量修复完成，${fixSuccessCount.value} 项成功，${fixFailedCount.value} 项失败`)
    } else if (status === 'failed') {
      message.error('修复任务失败，请检查主机是否在线')
    }
    selectedRowKeys.value = []
    loadFixableItems()
  } catch (error: any) {
    console.error('批量修复失败:', error)
    message.error('批量修复失败: ' + (error.response?.data?.message || error.message))
  } finally {
    fixing.value = false
  }
}

const pollFixTask = async (taskId: string): Promise<'completed' | 'failed' | 'timeout'> => {
  const pollInterval = 3000 // 3 秒轮询间隔
  const maxDuration = 30 * 60 * 1000 // 30 分钟安全上限
  const startTime = Date.now()

  // 用于增量检测新结果和新主机状态
  let prevResultCount = 0
  let prevHostStatusCount = 0
  let prevTaskStatus = ''

  while (Date.now() - startTime < maxDuration) {
    try {
      const task = await fixApi.getFixTask(taskId)
      fixProgress.value = task.progress
      fixSuccessCount.value = task.success_count
      fixFailedCount.value = task.failed_count

      // 从服务端同步总数
      if (task.total_count > 0) {
        fixTotal.value = task.total_count
      }

      // 状态变化日志
      if (task.status !== prevTaskStatus) {
        if (task.status === 'running' && prevTaskStatus !== 'running') {
          appendLog('info', '任务开始执行，正在下发到目标主机...')
        }
        prevTaskStatus = task.status
      }

      // 并行获取修复结果和主机状态
      const [resultsResponse, hostStatusResponse] = await Promise.all([
        fixApi.getFixResults(taskId, { page_size: 1000 }),
        fixApi.getFixTaskHostStatus(taskId, { page_size: 1000 }),
      ])

      const newResults = resultsResponse.items || []
      const newHostStatuses = hostStatusResponse.items || []

      // 增量输出主机状态日志
      if (newHostStatuses.length > prevHostStatusCount) {
        for (let i = prevHostStatusCount; i < newHostStatuses.length; i++) {
          const hs = newHostStatuses[i]
          if (hs.status === 'dispatched') {
            appendLog('info', `主机 ${hs.hostname} (${hs.ip_address}) 任务已下发`)
          } else if (hs.status === 'completed') {
            appendLog('success', `主机 ${hs.hostname} (${hs.ip_address}) 执行完成`)
          } else if (hs.status === 'failed') {
            appendLog('error', `主机 ${hs.hostname} (${hs.ip_address}) 执行失败${hs.error_message ? ': ' + hs.error_message : ''}`)
          } else if (hs.status === 'timeout') {
            appendLog('warn', `主机 ${hs.hostname} (${hs.ip_address}) 执行超时`)
          }
        }
        prevHostStatusCount = newHostStatuses.length
      }

      // 增量输出修复结果日志
      if (newResults.length > prevResultCount) {
        for (let i = prevResultCount; i < newResults.length; i++) {
          const r = newResults[i]
          if (r.command) {
            appendLog('cmd', `[${r.hostname}] $ ${r.command}`)
          }
          if (r.output) {
            appendLog('info', `[${r.hostname}] ${r.output.trim()}`)
          }
          if (r.status === 'success') {
            appendLog('success', `[${r.hostname}] ${r.title} — 修复成功`)
          } else if (r.status === 'failed') {
            appendLog('error', `[${r.hostname}] ${r.title} — 修复失败${r.error_msg ? ': ' + r.error_msg : ''}`)
          } else if (r.status === 'skipped') {
            appendLog('warn', `[${r.hostname}] ${r.title} — 跳过（无自动修复方案）`)
          }
        }
        prevResultCount = newResults.length
      }

      fixResults.value = newResults
      fixHostStatuses.value = newHostStatuses

      if (task.status === 'completed') {
        appendLog('success', `任务完成 — 成功 ${task.success_count}，失败 ${task.failed_count}`)
        fixing.value = false
        fixSuccess.value = task.failed_count === 0
        return 'completed'
      } else if (task.status === 'failed') {
        if (newResults.length === 0 && newHostStatuses.length === 0) {
          appendLog('error', '任务失败 — 所有目标主机离线，无法下发修复指令')
        } else {
          appendLog('error', '任务失败')
        }
        fixing.value = false
        fixSuccess.value = false
        return 'failed'
      }

      // 等待后继续轮询
      await new Promise(resolve => setTimeout(resolve, pollInterval))
    } catch (error) {
      console.error('轮询任务状态失败:', error)
      appendLog('warn', '网络异常，正在重试...')
      // 网络错误不中断轮询，等待后重试
      await new Promise(resolve => setTimeout(resolve, pollInterval))
    }
  }

  appendLog('warn', '轮询超时（30 分钟），请稍后查看结果')
  message.warning('任务执行超过 30 分钟，请稍后查看结果')
  fixing.value = false
  return 'timeout'
}

const handleCloseProgress = () => {
  progressModalVisible.value = false
  fixResults.value = []
  fixHostStatuses.value = []
  fixLogs.value = []
}

const copyCommand = (command: string) => {
  navigator.clipboard.writeText(command)
  message.success('已复制到剪贴板')
}

const filterHostOption = (input: string, option: any) => {
  // 获取主机名和IP地址进行匹配
  const host = filteredHosts.value.find(h => h.host_id === option.value)
  if (!host) return false

  const searchText = input.toLowerCase()
  const hostname = host.hostname.toLowerCase()
  const ip = host.ipv4[0] || ''

  return hostname.includes(searchText) || ip.includes(searchText)
}

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return colors[severity] || 'default'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = {
    critical: '严重',
    high: '高',
    medium: '中',
    low: '低',
  }
  return texts[severity] || severity
}

onMounted(() => {
  loadHosts()
  loadFixableItems()
})
</script>

<style scoped>
.baseline-fix-page {
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

.command-box {
  display: flex;
  align-items: center;
  gap: 8px;
  background: #f5f7fa;
  padding: 10px 14px;
  border-radius: 6px;
  border: 1px solid #e8e8e8;
}

.command-box code {
  flex: 1;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  color: #595959;
}

.fix-progress {
  padding: 16px 0;
}

.progress-info {
  display: flex;
  justify-content: space-between;
  margin-top: 12px;
  color: #666;
  font-size: 14px;
}

.live-log-panel {
  margin-top: 16px;
  max-height: 420px;
  overflow-y: auto;
  background: #1e1e1e;
  border-radius: 6px;
  padding: 12px 16px;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.7;
}

.live-log-line {
  display: flex;
  gap: 10px;
  align-items: baseline;
}

.log-time {
  color: #6a6a6a;
  flex-shrink: 0;
  user-select: none;
}

.log-text {
  word-break: break-all;
  white-space: pre-wrap;
}

.log-level-info .log-text {
  color: #d4d4d4;
}

.log-level-success .log-text {
  color: #73d13d;
}

.log-level-error .log-text {
  color: #EF4444;
}

.log-level-warn .log-text {
  color: #F59E0B;
}

.log-level-cmd .log-text {
  color: #69c0ff;
}

.log-cursor .log-text {
  color: #6a6a6a;
}
</style>
