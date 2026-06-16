<template>
  <div class="fim-events">
    <div class="page-header">
      <h2>FIM 变更事件</h2>
      <a-button @click="fetchEvents">
        <ReloadOutlined /> 刷新
      </a-button>
    </div>

    <!-- 统计卡片 -->
    <a-row :gutter="16" class="stat-cards">
      <a-col :span="4">
        <a-card size="small">
          <a-statistic title="总事件" :value="stats.total" />
        </a-card>
      </a-col>
      <a-col :span="4">
        <a-card size="small">
          <a-statistic title="待确认" :value="stats.pending" :value-style="{ color: '#F59E0B' }" />
        </a-card>
      </a-col>
      <a-col :span="3">
        <a-card size="small">
          <a-statistic title="严重" :value="stats.critical" :value-style="{ color: '#DC2626' }" />
        </a-card>
      </a-col>
      <a-col :span="3">
        <a-card size="small">
          <a-statistic title="高危" :value="stats.high" :value-style="{ color: '#fa541c' }" />
        </a-card>
      </a-col>
      <a-col :span="3">
        <a-card size="small">
          <a-statistic title="中危" :value="stats.medium" :value-style="{ color: '#F59E0B' }" />
        </a-card>
      </a-col>
      <a-col :span="3">
        <a-card size="small">
          <a-statistic title="低危" :value="stats.low" :value-style="{ color: '#3B82F6' }" />
        </a-card>
      </a-col>
      <a-col :span="4">
        <a-card size="small">
          <a-statistic title="变更类型" :value="`${stats.added}/${stats.changed}/${stats.removed}`" :value-style="{ fontSize: '18px' }" />
          <div style="color: #999; font-size: 12px">新增/变更/删除</div>
        </a-card>
      </a-col>
    </a-row>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-input
        v-model:value="filters.hostname"
        placeholder="主机名"
        style="width: 160px"
        allow-clear
        @change="handleSearch"
      >
        <template #prefix><SearchOutlined /></template>
      </a-input>
      <a-input
        v-model:value="filters.file_path"
        placeholder="文件路径"
        style="width: 200px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      />
      <a-select
        v-model:value="filters.status"
        placeholder="确认状态"
        style="width: 120px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="pending">待确认</a-select-option>
        <a-select-option value="confirmed">已确认</a-select-option>
        <a-select-option value="escalated">已升级</a-select-option>
      </a-select>
      <a-select
        v-model:value="filters.change_type"
        placeholder="变更类型"
        style="width: 120px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="added">新增</a-select-option>
        <a-select-option value="changed">变更</a-select-option>
        <a-select-option value="removed">删除</a-select-option>
      </a-select>
      <a-select
        v-model:value="filters.severity"
        placeholder="严重等级"
        style="width: 120px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="critical">严重</a-select-option>
        <a-select-option value="high">高危</a-select-option>
        <a-select-option value="medium">中危</a-select-option>
        <a-select-option value="low">低危</a-select-option>
      </a-select>
      <a-select
        v-model:value="filters.category"
        placeholder="分类"
        style="width: 120px; margin-left: 8px"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="binary">二进制</a-select-option>
        <a-select-option value="config">配置文件</a-select-option>
        <a-select-option value="auth">认证文件</a-select-option>
        <a-select-option value="log">日志</a-select-option>
        <a-select-option value="other">其他</a-select-option>
      </a-select>
      <a-range-picker
        v-model:value="dateRange"
        style="margin-left: 8px"
        @change="handleDateChange"
      />
    </div>

    <!-- 批量操作栏 -->
    <div v-if="selectedRowKeys.length > 0" class="batch-action-bar">
      <span>已选择 {{ selectedRowKeys.length }} 项</span>
      <a-button
        type="primary"
        size="small"
        :loading="batchConfirmLoading"
        @click="handleBatchConfirm"
      >
        批量确认
      </a-button>
      <a-button size="small" @click="selectedRowKeys = []">取消选择</a-button>
    </div>

    <!-- 事件表格 -->
    <a-table
      :columns="columns"
      :data-source="events"
      :loading="loading"
      :pagination="pagination"
      row-key="event_id"
      :row-selection="{
        selectedRowKeys,
        onChange: (keys: string[]) => selectedRowKeys = keys,
        getCheckboxProps: (record: FIMEvent) => ({ disabled: record.status !== 'pending' }),
      }"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'hostname'">
          <a-tooltip :title="record.host_id">
            {{ record.hostname || record.host_id?.substring(0, 8) }}
          </a-tooltip>
        </template>
        <template v-if="column.key === 'file_path'">
          <a-tooltip :title="record.file_path">
            <span class="file-path">{{ record.file_path }}</span>
          </a-tooltip>
        </template>
        <template v-if="column.key === 'change_type'">
          <a-tag :color="getChangeTypeColor(record.change_type)">
            {{ getChangeTypeText(record.change_type) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'severity'">
          <a-tag :color="getSeverityColor(record.severity)">
            {{ getSeverityText(record.severity) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'category'">
          <a-tag>{{ getCategoryText(record.category) }}</a-tag>
        </template>
        <template v-if="column.key === 'status'">
          <a-tag :color="getStatusColor(record.status)" :bordered="false">
            {{ getStatusText(record.status) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a @click="showDetail(record)">详情</a>
            <a v-if="record.status === 'pending'" @click="openConfirmModal(record)">确认</a>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 事件详情弹窗 -->
    <a-modal
      v-model:open="detailVisible"
      title="变更事件详情"
      :width="640"
      :footer="null"
    >
      <template v-if="selectedEvent">
        <a-descriptions :column="2" bordered size="small">
          <a-descriptions-item label="事件 ID" :span="2">
            <span style="font-family: monospace; font-size: 12px">{{ selectedEvent.event_id }}</span>
          </a-descriptions-item>
          <a-descriptions-item label="主机名">{{ selectedEvent.hostname }}</a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="getStatusColor(selectedEvent.status)" :bordered="false">
              {{ getStatusText(selectedEvent.status) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="文件路径" :span="2">
            <code>{{ selectedEvent.file_path }}</code>
          </a-descriptions-item>
          <a-descriptions-item label="变更类型">
            <a-tag :color="getChangeTypeColor(selectedEvent.change_type)">
              {{ getChangeTypeText(selectedEvent.change_type) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="严重等级">
            <a-tag :color="getSeverityColor(selectedEvent.severity)">
              {{ getSeverityText(selectedEvent.severity) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="分类">{{ getCategoryText(selectedEvent.category) }}</a-descriptions-item>
          <a-descriptions-item label="检测时间">{{ selectedEvent.detected_at }}</a-descriptions-item>
          <template v-if="selectedEvent.confirmed_by">
            <a-descriptions-item label="确认人">{{ selectedEvent.confirmed_by }}</a-descriptions-item>
            <a-descriptions-item label="确认时间">{{ selectedEvent.confirmed_at }}</a-descriptions-item>
            <a-descriptions-item label="确认原因" :span="2">{{ selectedEvent.confirm_reason || '-' }}</a-descriptions-item>
          </template>
        </a-descriptions>

        <a-divider>变更详情</a-divider>
        <a-descriptions :column="2" bordered size="small" v-if="selectedEvent.change_detail">
          <a-descriptions-item label="文件大小（前）">
            {{ selectedEvent.change_detail.size_before || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="文件大小（后）">
            {{ selectedEvent.change_detail.size_after || '-' }}
          </a-descriptions-item>
          <a-descriptions-item label="哈希变更">
            <a-tag :color="selectedEvent.change_detail.hash_changed ? 'red' : 'green'">
              {{ selectedEvent.change_detail.hash_changed ? '是' : '否' }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="权限变更">
            <a-tag :color="selectedEvent.change_detail.permission_changed ? 'red' : 'green'">
              {{ selectedEvent.change_detail.permission_changed ? '是' : '否' }}
            </a-tag>
          </a-descriptions-item>
          <template v-if="selectedEvent.change_detail.hash_before">
            <a-descriptions-item label="哈希（前）" :span="2">
              <code style="font-size: 11px; word-break: break-all">{{ selectedEvent.change_detail.hash_before }}</code>
            </a-descriptions-item>
            <a-descriptions-item label="哈希（后）" :span="2">
              <code style="font-size: 11px; word-break: break-all">{{ selectedEvent.change_detail.hash_after }}</code>
            </a-descriptions-item>
          </template>
          <template v-if="selectedEvent.change_detail.mode_before">
            <a-descriptions-item label="权限（前）">{{ selectedEvent.change_detail.mode_before }}</a-descriptions-item>
            <a-descriptions-item label="权限（后）">{{ selectedEvent.change_detail.mode_after }}</a-descriptions-item>
          </template>
          <a-descriptions-item label="属主变更">
            <a-tag :color="selectedEvent.change_detail.owner_changed ? 'red' : 'green'">
              {{ selectedEvent.change_detail.owner_changed ? '是' : '否' }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="属性标记">
            <code>{{ selectedEvent.change_detail.attributes || '-' }}</code>
          </a-descriptions-item>
        </a-descriptions>
      </template>
    </a-modal>

    <!-- 确认弹窗 -->
    <a-modal
      v-model:open="confirmModalVisible"
      title="确认变更为合法"
      @ok="doConfirm"
      :confirm-loading="confirmLoading"
    >
      <p>确认文件 <code>{{ confirmTarget?.file_path }}</code> 的变更为合法操作？</p>
      <a-form-item label="确认原因">
        <a-textarea v-model:value="confirmReason" :rows="3" placeholder="请输入确认原因（如：运维更新配置）" />
      </a-form-item>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { SearchOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { fimApi } from '@/api/fim'
import type { FIMEvent, FIMEventStats } from '@/api/types'
import type { Dayjs } from 'dayjs'

const loading = ref(false)
const events = ref<FIMEvent[]>([])
const detailVisible = ref(false)
const selectedEvent = ref<FIMEvent | null>(null)
const dateRange = ref<[Dayjs, Dayjs] | null>(null)
const selectedRowKeys = ref<string[]>([])
const batchConfirmLoading = ref(false)

// 确认弹窗
const confirmModalVisible = ref(false)
const confirmTarget = ref<FIMEvent | null>(null)
const confirmReason = ref('')
const confirmLoading = ref(false)

const stats = reactive<FIMEventStats>({
  total: 0,
  pending: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  added: 0,
  removed: 0,
  changed: 0,
  by_category: {},
  top_hosts: [],
  trend: [],
})

const filters = reactive({
  hostname: '',
  file_path: '',
  status: undefined as string | undefined,
  change_type: undefined as string | undefined,
  severity: undefined as string | undefined,
  category: undefined as string | undefined,
  date_from: undefined as string | undefined,
  date_to: undefined as string | undefined,
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: '主机名', key: 'hostname', width: 130 },
  { title: '文件路径', key: 'file_path', ellipsis: true },
  { title: '变更类型', key: 'change_type', width: 90, align: 'center' as const },
  { title: '严重等级', key: 'severity', width: 90, align: 'center' as const },
  { title: '分类', key: 'category', width: 90, align: 'center' as const },
  { title: '状态', key: 'status', width: 90, align: 'center' as const },
  { title: '检测时间', dataIndex: 'detected_at', width: 170 },
  { title: '操作', key: 'action', width: 100 },
]

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' }
  return colors[severity] || 'default'
}

const getSeverityText = (severity: string) => {
  const texts: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危' }
  return texts[severity] || severity
}

const getChangeTypeColor = (type: string) => {
  const colors: Record<string, string> = { added: 'green', removed: 'red', changed: 'orange' }
  return colors[type] || 'default'
}

const getChangeTypeText = (type: string) => {
  const texts: Record<string, string> = { added: '新增', removed: '删除', changed: '变更' }
  return texts[type] || type
}

const getCategoryText = (category: string) => {
  const texts: Record<string, string> = { binary: '二进制', config: '配置文件', auth: '认证文件', ssh: 'SSH', log: '日志', other: '其他' }
  return texts[category] || category || '-'
}

const getStatusColor = (status: string) => {
  const colors: Record<string, string> = { pending: 'warning', confirmed: 'success', escalated: 'error' }
  return colors[status] || 'default'
}

const getStatusText = (status: string) => {
  const texts: Record<string, string> = { pending: '待确认', confirmed: '已确认', escalated: '已升级' }
  return texts[status] || status
}

const fetchEvents = async () => {
  loading.value = true
  try {
    const res = await fimApi.listEvents({
      page: pagination.current,
      page_size: pagination.pageSize,
      hostname: filters.hostname || undefined,
      file_path: filters.file_path || undefined,
      status: filters.status,
      change_type: filters.change_type,
      severity: filters.severity,
      category: filters.category,
      date_from: filters.date_from,
      date_to: filters.date_to,
    })
    events.value = res.items || []
    pagination.total = res.total
  } catch {
    // API 客户端已处理错误提示
  } finally {
    loading.value = false
  }
}

const fetchStats = async () => {
  try {
    const res = await fimApi.getEventStats(30)
    Object.assign(stats, res)
  } catch {
    // 静默处理
  }
}

const handleSearch = () => {
  pagination.current = 1
  fetchEvents()
}

const handleDateChange = (dates: [Dayjs, Dayjs] | null) => {
  if (dates) {
    filters.date_from = dates[0].format('YYYY-MM-DD')
    filters.date_to = dates[1].format('YYYY-MM-DD')
  } else {
    filters.date_from = undefined
    filters.date_to = undefined
  }
  handleSearch()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchEvents()
}

const showDetail = (event: FIMEvent) => {
  selectedEvent.value = event
  detailVisible.value = true
}

const openConfirmModal = (event: FIMEvent) => {
  confirmTarget.value = event
  confirmReason.value = ''
  confirmModalVisible.value = true
}

const doConfirm = async () => {
  if (!confirmTarget.value) return
  confirmLoading.value = true
  try {
    await fimApi.confirmEvent(confirmTarget.value.event_id, { reason: confirmReason.value })
    message.success('事件已确认')
    confirmModalVisible.value = false
    fetchEvents()
    fetchStats()
  } catch (error) {
    console.error('确认事件失败:', error)
  } finally {
    confirmLoading.value = false
  }
}

const handleBatchConfirm = async () => {
  if (selectedRowKeys.value.length === 0) return
  batchConfirmLoading.value = true
  try {
    const pendingIds = events.value
      .filter(e => selectedRowKeys.value.includes(e.event_id) && e.status === 'pending')
      .map(e => e.event_id)
    const res = await fimApi.batchConfirmEvents(pendingIds, '批量确认')
    message.success(`已确认 ${res.confirmed} 个事件`)
    selectedRowKeys.value = []
    fetchEvents()
    fetchStats()
  } catch (error) {
    console.error('批量确认事件失败:', error)
  } finally {
    batchConfirmLoading.value = false
  }
}

onMounted(() => {
  fetchEvents()
  fetchStats()
})
</script>

<style scoped>
.fim-events { padding: 0; }

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
  align-items: center;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 4px;
}

.batch-action-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 12px;
  background: var(--mxsec-primary-bg);
  border: 1px solid #BEDAFF;
  border-radius: 6px;
  font-size: 13px;
}

.file-path { font-family: monospace; font-size: 13px; }
</style>
