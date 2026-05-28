<template>
  <div class="scan-schedules-page">
    <div class="page-header">
      <h2>扫描计划</h2>
      <a-button type="primary" @click="openCreateModal">
        <template #icon><PlusOutlined /></template>
        新建计划
      </a-button>
    </div>

    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <div class="filter-actions">
            <a-button @click="loadSchedules">刷新</a-button>
          </div>
        </div>

        <a-table
          :columns="columns"
          :data-source="schedules"
          :loading="loading"
          size="middle"
          row-key="id"
          :pagination="false"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'scanType'">
              <a-tag :color="scanTypeColor(record.scanType)">
                {{ scanTypeText(record.scanType) }}
              </a-tag>
            </template>
            <template v-else-if="column.key === 'enabled'">
              <a-switch
                :checked="record.enabled"
                :loading="toggleLoadingId === record.id"
                @change="handleToggle(record)"
              />
            </template>
            <template v-else-if="column.key === 'lastRunAt'">
              {{ formatDate(record.lastRunAt) }}
            </template>
            <template v-else-if="column.key === 'nextRunAt'">
              {{ formatDate(record.nextRunAt) }}
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="showExecutions(record)">
                  历史
                </a-button>
                <a-button type="link" size="small" @click="openEditModal(record)">
                  编辑
                </a-button>
                <a-popconfirm
                  title="确定要删除此扫描计划吗？"
                  @confirm="handleDelete(record)"
                >
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 新建/编辑弹窗 -->
    <a-modal
      v-model:open="modalVisible"
      :title="editingSchedule ? '编辑扫描计划' : '新建扫描计划'"
      :confirm-loading="submitting"
      @ok="handleSubmit"
      @cancel="resetForm"
    >
      <a-form layout="vertical">
        <a-form-item label="计划名称" required>
          <a-input
            v-model:value="form.name"
            placeholder="请输入计划名称"
          />
        </a-form-item>
        <a-form-item label="扫描类型" required>
          <a-select v-model:value="form.scanType" placeholder="请选择扫描类型">
            <a-select-option value="full_scan">全量扫描</a-select-option>
            <a-select-option value="incremental_scan">增量扫描</a-select-option>
            <a-select-option value="sync_only">仅同步</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="Cron 表达式" required>
          <a-input
            v-model:value="form.cronExpr"
            placeholder="例如: 0 2 * * * （每天凌晨 2 点）"
          />
          <div class="form-hint">支持标准 5 位 Cron 表达式，格式：分 时 日 月 周</div>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 执行历史抽屉 -->
    <a-drawer
      v-model:open="execDrawerVisible"
      :title="`执行历史 - ${execDrawerTitle}`"
      width="720"
      :destroy-on-close="true"
    >
      <a-table
        :columns="execColumns"
        :data-source="execData"
        :loading="execLoading"
        size="small"
        row-key="id"
        :pagination="{
          current: execPagination.current,
          pageSize: execPagination.pageSize,
          total: execPagination.total,
          showSizeChanger: false,
        }"
        @change="handleExecTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'id'">
            <router-link :to="{ name: 'VulnScanExecutionDetail', params: { id: record.id } }">
              #{{ record.id }}
            </router-link>
          </template>
          <template v-else-if="column.key === 'status'">
            <a-tag :color="execStatusColor(record.status)" :bordered="false">
              {{ execStatusText(record.status) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'scanType'">
            <a-tag :color="scanTypeColor(record.scanType)">
              {{ scanTypeText(record.scanType) }}
            </a-tag>
          </template>
          <template v-else-if="column.key === 'errorMsg'">
            <template v-if="record.errorMsg && record.errorMsg.startsWith('[')">
              <a-tag
                v-for="src in parseSourceResults(record.errorMsg)"
                :key="src.name"
                :color="src.status === 'success' ? 'green' : src.status === 'skipped' ? 'default' : 'red'"
                :bordered="false"
                size="small"
                style="margin-right: 4px"
              >
                <a-tooltip v-if="src.error" :title="src.error">{{ src.name }}</a-tooltip>
                <template v-else>{{ src.name }}</template>
              </a-tag>
            </template>
            <a-tooltip v-else-if="record.errorMsg" :title="record.errorMsg">
              <span class="exec-error-text">{{ record.errorMsg }}</span>
            </a-tooltip>
            <span v-else>-</span>
          </template>
          <template v-else-if="column.key === 'startedAt'">
            {{ formatDate(record.startedAt) }}
          </template>
          <template v-else-if="column.key === 'duration'">
            {{ record.duration ? record.duration + 's' : '-' }}
          </template>
        </template>
      </a-table>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, reactive } from 'vue'
import { message } from 'ant-design-vue'
import { PlusOutlined } from '@ant-design/icons-vue'
import { scanSchedulesApi } from '@/api/scan-schedules'
import type { ScanSchedule, ScanScheduleExecution } from '@/api/scan-schedules'

const loading = ref(false)
const schedules = ref<ScanSchedule[]>([])
const modalVisible = ref(false)
const submitting = ref(false)
const editingSchedule = ref<ScanSchedule | null>(null)
const toggleLoadingId = ref<number | null>(null)

const form = reactive({
  name: '',
  scanType: undefined as string | undefined,
  cronExpr: '',
})

const columns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '计划名称', dataIndex: 'name', width: 180 },
  { title: '扫描类型', key: 'scanType', width: 120 },
  { title: 'Cron 表达式', dataIndex: 'cronExpr', width: 160 },
  { title: '启用状态', key: 'enabled', width: 100 },
  { title: '上次执行', key: 'lastRunAt', width: 170 },
  { title: '下次执行', key: 'nextRunAt', width: 170 },
  { title: '操作', key: 'action', width: 140, fixed: 'right' as const },
]

const scanTypeColor = (type: string) => {
  const map: Record<string, string> = {
    full_scan: 'blue',
    incremental_scan: 'cyan',
    sync_only: 'green',
  }
  return map[type] || 'default'
}

const scanTypeText = (type: string) => {
  const map: Record<string, string> = {
    full_scan: '全量扫描',
    incremental_scan: '增量扫描',
    sync_only: '仅同步',
  }
  return map[type] || type
}

const formatDate = (dateStr?: string): string => {
  if (!dateStr) return '-'
  return dateStr.replace('T', ' ').substring(0, 19)
}

const loadSchedules = async () => {
  loading.value = true
  try {
    const data = await scanSchedulesApi.list()
    schedules.value = data ?? []
  } catch {
    schedules.value = []
  } finally {
    loading.value = false
  }
}

const openCreateModal = () => {
  editingSchedule.value = null
  resetForm()
  modalVisible.value = true
}

const openEditModal = (record: ScanSchedule) => {
  editingSchedule.value = record
  form.name = record.name
  form.scanType = record.scanType
  form.cronExpr = record.cronExpr
  modalVisible.value = true
}

const resetForm = () => {
  form.name = ''
  form.scanType = undefined
  form.cronExpr = ''
}

const handleSubmit = async () => {
  if (!form.name || !form.scanType || !form.cronExpr) {
    message.warning('请填写完整的计划信息')
    return
  }
  submitting.value = true
  try {
    if (editingSchedule.value) {
      await scanSchedulesApi.update(editingSchedule.value.id, {
        name: form.name,
        scanType: form.scanType,
        cronExpr: form.cronExpr,
      })
      message.success('扫描计划已更新')
    } else {
      await scanSchedulesApi.create({
        name: form.name,
        scanType: form.scanType,
        cronExpr: form.cronExpr,
      })
      message.success('扫描计划已创建')
    }
    modalVisible.value = false
    resetForm()
    loadSchedules()
  } catch {
    message.error(editingSchedule.value ? '更新失败' : '创建失败')
  } finally {
    submitting.value = false
  }
}

const handleToggle = async (record: ScanSchedule) => {
  toggleLoadingId.value = record.id
  try {
    await scanSchedulesApi.toggle(record.id)
    message.success(record.enabled ? '已禁用' : '已启用')
    loadSchedules()
  } catch {
    message.error('操作失败')
  } finally {
    toggleLoadingId.value = null
  }
}

const handleDelete = async (record: ScanSchedule) => {
  try {
    await scanSchedulesApi.delete(record.id)
    message.success('扫描计划已删除')
    loadSchedules()
  } catch {
    message.error('删除失败')
  }
}

// === 执行历史 ===
const execDrawerVisible = ref(false)
const execDrawerTitle = ref('')
const execLoading = ref(false)
const execData = ref<ScanScheduleExecution[]>([])
const execScheduleId = ref(0)
const execPagination = reactive({ current: 1, pageSize: 20, total: 0 })

const execColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '扫描类型', key: 'scanType', width: 100 },
  { title: '状态', key: 'status', width: 80 },
  { title: '开始时间', key: 'startedAt', width: 170 },
  { title: '耗时', key: 'duration', width: 80 },
  { title: '详情', key: 'errorMsg', ellipsis: true },
]

const execStatusColor = (status: string) => {
  const map: Record<string, string> = { success: 'green', failed: 'red', running: 'blue' }
  return map[status] || 'default'
}

const execStatusText = (status: string) => {
  const map: Record<string, string> = { success: '成功', failed: '失败', running: '执行中' }
  return map[status] || status
}

const parseSourceResults = (msg: string) => {
  try {
    return JSON.parse(msg) as { name: string; status: string; error?: string }[]
  } catch {
    return []
  }
}

const showExecutions = async (record: ScanSchedule) => {
  execScheduleId.value = record.id
  execDrawerTitle.value = record.name
  execPagination.current = 1
  execDrawerVisible.value = true
  await loadExecutions()
}

const loadExecutions = async () => {
  execLoading.value = true
  try {
    const data = await scanSchedulesApi.listExecutions(
      execScheduleId.value,
      execPagination.current,
      execPagination.pageSize,
    )
    execData.value = data?.items ?? []
    execPagination.total = data?.total ?? 0
  } catch {
    execData.value = []
  } finally {
    execLoading.value = false
  }
}

const handleExecTableChange = (pag: any) => {
  execPagination.current = pag.current
  loadExecutions()
}

onMounted(() => {
  loadSchedules()
})
</script>

<style scoped>
.scan-schedules-page { width: 100%; }

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

.dashboard-card { background: var(--mxsec-card-bg); border: 1px solid var(--mxsec-border); border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 12px; margin-bottom: 16px; }
.filter-actions { margin-left: auto; }

.form-hint {
  margin-top: 4px;
  font-size: 12px;
  color: var(--mxsec-text-3);
}

.exec-error-text {
  color: #EF4444;
  font-size: 12px;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 200px;
  display: inline-block;
}
</style>
