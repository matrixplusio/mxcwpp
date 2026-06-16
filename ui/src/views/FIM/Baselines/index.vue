<template>
  <div class="fim-baselines">
    <div class="page-header">
      <h2>基线管理</h2>
      <a-button @click="fetchBaselines">
        <ReloadOutlined /> 刷新
      </a-button>
    </div>

    <!-- 筛选栏 -->
    <div class="filter-bar">
      <a-select
        v-model:value="filterStatus"
        placeholder="基线状态"
        style="width: 140px"
        allow-clear
        @change="handleFilterChange"
      >
        <a-select-option value="pending">待审批</a-select-option>
        <a-select-option value="approved">已审批</a-select-option>
        <a-select-option value="outdated">已过期</a-select-option>
      </a-select>
    </div>

    <!-- 批量操作栏 -->
    <div v-if="selectedRowKeys.length > 0" class="batch-action-bar">
      <span>已选择 {{ selectedRowKeys.length }} 项</span>
      <a-button
        type="primary"
        size="small"
        :loading="batchApproveLoading"
        @click="handleBatchApprove"
      >
        批量审批
      </a-button>
      <a-button size="small" @click="selectedRowKeys = []">取消选择</a-button>
    </div>

    <!-- 基线列表 -->
    <a-table
      :columns="columns"
      :data-source="baselines"
      :loading="loading"
      :pagination="pagination"
      row-key="id"
      :row-selection="{
        selectedRowKeys,
        onChange: (keys: number[]) => selectedRowKeys = keys,
        getCheckboxProps: (record: FIMBaseline) => ({ disabled: record.status !== 'pending' }),
      }"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'policy'">
          {{ record.policy_id?.substring(0, 8) }}
        </template>
        <template v-if="column.key === 'host'">
          {{ record.hostname || record.host_id?.substring(0, 8) }}
        </template>
        <template v-if="column.key === 'status'">
          <a-tag :color="statusColor(record.status)" :bordered="false">
            {{ statusText(record.status) }}
          </a-tag>
        </template>
        <template v-if="column.key === 'approved'">
          <template v-if="record.approved_by">
            {{ record.approved_by }} ({{ record.approved_at }})
          </template>
          <span v-else class="text-muted">-</span>
        </template>
        <template v-if="column.key === 'action'">
          <a-space>
            <a @click="showDetail(record)">详情</a>
            <a v-if="record.status === 'pending'" @click="handleApprove(record)">审批</a>
            <a v-if="record.status === 'pending'" class="danger-link" @click="handleReject(record)">拒绝</a>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 基线详情弹窗 -->
    <a-modal
      v-model:open="detailVisible"
      title="基线详情"
      :width="900"
      :footer="null"
    >
      <template v-if="detailBaseline">
        <a-descriptions :column="2" bordered size="small" style="margin-bottom: 16px">
          <a-descriptions-item label="策略 ID">{{ detailBaseline.policy_id }}</a-descriptions-item>
          <a-descriptions-item label="主机名">{{ detailBaseline.hostname }}</a-descriptions-item>
          <a-descriptions-item label="版本">v{{ detailBaseline.version }}</a-descriptions-item>
          <a-descriptions-item label="状态">
            <a-tag :color="statusColor(detailBaseline.status)" :bordered="false">
              {{ statusText(detailBaseline.status) }}
            </a-tag>
          </a-descriptions-item>
          <a-descriptions-item label="文件条目数">{{ detailBaseline.entry_count }}</a-descriptions-item>
          <a-descriptions-item label="创建时间">{{ detailBaseline.created_at }}</a-descriptions-item>
        </a-descriptions>

        <a-table
          :columns="entryColumns"
          :data-source="detailEntries"
          :loading="detailLoading"
          :pagination="entryPagination"
          size="small"
          row-key="id"
          @change="handleEntryTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'file_path'">
              <a-tooltip :title="record.file_path">
                <span class="file-path">{{ record.file_path }}</span>
              </a-tooltip>
            </template>
            <template v-if="column.key === 'sha256'">
              <a-tooltip :title="record.sha256">
                <span class="hash-preview">{{ record.sha256?.substring(0, 16) }}...</span>
              </a-tooltip>
            </template>
          </template>
        </a-table>
      </template>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ReloadOutlined } from '@ant-design/icons-vue'
import { message, Modal } from 'ant-design-vue'
import { fimApi } from '@/api/fim'
import type { FIMBaseline, FIMBaselineEntry } from '@/api/types'

const loading = ref(false)
const baselines = ref<FIMBaseline[]>([])
const filterStatus = ref<string>()
const selectedRowKeys = ref<number[]>([])
const batchApproveLoading = ref(false)

// 详情
const detailVisible = ref(false)
const detailBaseline = ref<FIMBaseline | null>(null)
const detailEntries = ref<FIMBaselineEntry[]>([])
const detailLoading = ref(false)

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const entryPagination = reactive({
  current: 1,
  pageSize: 50,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const columns = [
  { title: 'ID', dataIndex: 'id', width: 60 },
  { title: '策略', key: 'policy', width: 120 },
  { title: '主机', key: 'host', width: 150 },
  { title: '版本', dataIndex: 'version', width: 70 },
  { title: '文件数', dataIndex: 'entry_count', width: 80 },
  { title: '状态', key: 'status', width: 90 },
  { title: '审批信息', key: 'approved', width: 200 },
  { title: '创建时间', dataIndex: 'created_at', width: 170 },
  { title: '操作', key: 'action', width: 150, fixed: 'right' as const },
]

const entryColumns = [
  { title: '文件路径', key: 'file_path', ellipsis: true },
  { title: 'SHA256', key: 'sha256', width: 180 },
  { title: '大小', dataIndex: 'file_size', width: 80 },
  { title: '权限', dataIndex: 'file_mode', width: 110 },
  { title: 'UID', dataIndex: 'uid', width: 60 },
  { title: 'GID', dataIndex: 'gid', width: 60 },
]

const statusColor = (status: string) => {
  const map: Record<string, string> = { pending: 'warning', approved: 'success', outdated: 'default' }
  return map[status] || 'default'
}

const statusText = (status: string) => {
  const map: Record<string, string> = { pending: '待审批', approved: '已审批', outdated: '已过期' }
  return map[status] || status
}

const fetchBaselines = async () => {
  loading.value = true
  try {
    const res = await fimApi.listBaselines({
      page: pagination.current,
      page_size: pagination.pageSize,
      status: filterStatus.value,
    })
    baselines.value = res.items || []
    pagination.total = res.total
  } catch {
    baselines.value = []
  } finally {
    loading.value = false
  }
}

const handleFilterChange = () => {
  pagination.current = 1
  fetchBaselines()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  fetchBaselines()
}

const showDetail = async (record: FIMBaseline) => {
  detailBaseline.value = record
  detailVisible.value = true
  entryPagination.current = 1
  await fetchEntries(record.id)
}

const fetchEntries = async (baselineId: number) => {
  detailLoading.value = true
  try {
    const res = await fimApi.getBaseline(baselineId, {
      entry_page: entryPagination.current,
      entry_page_size: entryPagination.pageSize,
    })
    detailEntries.value = res.entries || []
    entryPagination.total = res.entry_total
  } catch {
    detailEntries.value = []
  } finally {
    detailLoading.value = false
  }
}

const handleEntryTableChange = (pag: any) => {
  entryPagination.current = pag.current
  entryPagination.pageSize = pag.pageSize
  if (detailBaseline.value) {
    fetchEntries(detailBaseline.value.id)
  }
}

const handleApprove = (record: FIMBaseline) => {
  Modal.confirm({
    title: '审批基线',
    content: `确认审批主机 ${record.hostname} 的基线（${record.entry_count} 个文件）？审批后该基线将作为完整性对比基准。`,
    onOk: async () => {
      try {
        await fimApi.approveBaseline(record.id)
        message.success('基线已审批')
        fetchBaselines()
      } catch (error) {
        console.error('审批基线失败:', error)
      }
    },
  })
}

const handleReject = (record: FIMBaseline) => {
  Modal.confirm({
    title: '拒绝基线',
    content: `确认拒绝并删除主机 ${record.hostname} 的候选基线？`,
    okType: 'danger',
    onOk: async () => {
      try {
        await fimApi.rejectBaseline(record.id)
        message.success('基线已拒绝')
        fetchBaselines()
      } catch (error) {
        console.error('拒绝基线失败:', error)
      }
    },
  })
}

const handleBatchApprove = async () => {
  if (selectedRowKeys.value.length === 0) return
  batchApproveLoading.value = true
  try {
    const pendingIds = baselines.value
      .filter(b => selectedRowKeys.value.includes(b.id) && b.status === 'pending')
      .map(b => b.id)
    const res = await fimApi.batchApproveBaselines(pendingIds)
    message.success(`已审批 ${res.approved} 个基线`)
    selectedRowKeys.value = []
    fetchBaselines()
  } catch (error) {
    console.error('批量审批基线失败:', error)
  } finally {
    batchApproveLoading.value = false
  }
}

onMounted(() => {
  fetchBaselines()
})
</script>

<style scoped>
.fim-baselines { padding: 0; }

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.page-header h2 { margin: 0; font-size: 20px; }

.filter-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
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
.hash-preview { font-family: monospace; font-size: 12px; color: var(--mxsec-text-2); }
.text-muted { color: var(--mxsec-text-3); font-size: 12px; }
.danger-link { color: #EF4444; }
</style>
